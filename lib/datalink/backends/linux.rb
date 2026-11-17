# frozen_string_literal: true

require "socket"
require "datalink/backends/base"

module Datalink
  module Backends
    # Linux raw-Ethernet backend over AF_PACKET / SOCK_RAW.
    #
    # Needs root or the CAP_NET_RAW capability. Binds to one interface by
    # name and sends/receives whole Ethernet frames (the kernel appends
    # the FCS on send and strips it on receive).
    #
    # Modernized from the original: no shelling out, timeouts via
    # IO.select instead of sleep/retry, and clear errors on EPERM.
    #
    # Each captured frame carries its packet type, from the sockaddr_ll
    # recvfrom answers. With ETH_P_ALL the socket also sees frames this
    # host sends out of the interface, through another socket or its own
    # IP stack, as :outgoing. Its own sends it never sees. Measured on
    # Linux 7.0 over a veth pair. ignore_outgoing: true drops the
    # outgoing ones, which a program that forwards frames needs, or it
    # forwards the host's own traffic.
    class Linux < Base
      PF_PACKET    = 17
      ETH_P_ALL    = 0x0003
      SIOCGIFINDEX = 0x8933
      SIOCGIFFLAGS = 0x8913
      SIOCSIFFLAGS = 0x8914
      IFF_PROMISC  = 0x0100
      IFNAMSIZ     = 16
      # linux/socket.h and linux/if_packet.h. PACKET_IGNORE_OUTGOING is
      # in kernels from 4.20.
      SOL_PACKET             = 263
      PACKET_IGNORE_OUTGOING = 23
      # sockaddr_ll: family u16, protocol be16, ifindex s32, hatype u16,
      # then pkttype u8 at offset 10.
      PKTTYPE_OFFSET = 10
      PACKET_TYPES = { 0 => :host, 1 => :broadcast, 2 => :multicast,
                       3 => :otherhost, 4 => :outgoing }.freeze

      def self.available?
        RUBY_PLATFORM.include?("linux")
      end

      # The packet type in a sockaddr_ll, as a Symbol from PACKET_TYPES,
      # or the number when the kernel sends one not listed there. nil
      # when the address is too short to hold one.
      def self.packet_type(sockaddr)
        return nil if sockaddr.nil? || sockaddr.bytesize <= PKTTYPE_OFFSET

        n = sockaddr.getbyte(PKTTYPE_OFFSET)
        PACKET_TYPES.fetch(n, n)
      end

      def initialize(interface, recv_timeout: nil, protocol: ETH_P_ALL, promiscuous: false,
                     ignore_outgoing: false)
        super(interface, recv_timeout: recv_timeout)
        @protocol = protocol
        @promiscuous = promiscuous
        @ignore_outgoing = ignore_outgoing
        @filter_outgoing = false
      end

      def ignore_outgoing?
        @ignore_outgoing
      end

      def open
        # htons on the protocol: the kernel wants it in network order.
        proto_be = [@protocol].pack("s>").unpack1("s")
        @socket = ::Socket.new(PF_PACKET, ::Socket::SOCK_RAW, proto_be)
        bind_to_interface
        enable_promiscuous if @promiscuous
        drop_outgoing if @ignore_outgoing
        @open = true
        self
      rescue Errno::EPERM, Errno::EACCES => e
        raise PermissionError, "AF_PACKET needs root or CAP_NET_RAW: #{e.message}"
      end

      def recv
        ensure_open
        deadline = @recv_timeout && (monotonic + @recv_timeout)
        loop do
          if deadline
            left = deadline - monotonic
            ready = left.positive? && IO.select([@socket], nil, nil, left)
            raise TimeoutError, "no frame within #{@recv_timeout}s" unless ready
          end
          data, addr = @socket.recvfrom(65_535)
          type = self.class.packet_type(addr.respond_to?(:to_sockaddr) ? addr.to_sockaddr : addr)
          next if @filter_outgoing && type == :outgoing

          return CapturedFrame.new(data, Time.now, type)
        end
      end

      def close
        disable_promiscuous if @promiscuous && @open
        @socket&.close
        @open = false
      end

      private

      def do_send(bytes)
        ensure_open
        @socket.send(bytes, 0)
      end

      def bind_to_interface
        ifreq = [@interface].pack("a#{IFNAMSIZ}")
        @socket.ioctl(SIOCGIFINDEX, ifreq)
        ifindex = ifreq[IFNAMSIZ, 4].unpack1("i")
        # struct sockaddr_ll: family, protocol(be), ifindex, then zeros.
        proto_be = [@protocol].pack("s>")
        sll = [PF_PACKET].pack("s") + proto_be + [ifindex].pack("i") + ("\x00" * 12)
        @socket.bind(sll)
      end

      def enable_promiscuous
        set_flags(read_flags | IFF_PROMISC)
      end

      def disable_promiscuous
        set_flags(read_flags & ~IFF_PROMISC)
      end

      def read_flags
        ifreq = [@interface].pack("a#{IFNAMSIZ}")
        @socket.ioctl(SIOCGIFFLAGS, ifreq)
        ifreq[IFNAMSIZ, 2].unpack1("s")
      end

      def set_flags(flags)
        ifreq = [@interface].pack("a#{IFNAMSIZ}") + [flags].pack("s")
        @socket.ioctl(SIOCSIFFLAGS, ifreq)
      end

      def ensure_open
        raise Error, "backend not open" unless @open
      end

      # Ask the kernel to drop outgoing frames. A kernel without the
      # option refuses it, and recv then drops them itself.
      def drop_outgoing
        @socket.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, [1].pack("i"))
        @filter_outgoing = false
      rescue SystemCallError
        @filter_outgoing = true
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      # Unit tests only: put a stand-in where the raw socket goes, so recv
      # runs with no privileges.
      def attach_for_test(socket, filter_outgoing:)
        @socket = socket
        @filter_outgoing = filter_outgoing
        @open = true
      end
    end
  end
end
