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
    class Linux < Base
      PF_PACKET    = 17
      ETH_P_ALL    = 0x0003
      SIOCGIFINDEX = 0x8933
      SIOCGIFFLAGS = 0x8913
      SIOCSIFFLAGS = 0x8914
      IFF_PROMISC  = 0x0100
      IFNAMSIZ     = 16

      def self.available?
        RUBY_PLATFORM.include?("linux")
      end

      def initialize(interface, recv_timeout: nil, protocol: ETH_P_ALL, promiscuous: false)
        super(interface, recv_timeout: recv_timeout)
        @protocol = protocol
        @promiscuous = promiscuous
      end

      def open
        # htons on the protocol: the kernel wants it in network order.
        proto_be = [@protocol].pack("s>").unpack1("s")
        @socket = ::Socket.new(PF_PACKET, ::Socket::SOCK_RAW, proto_be)
        bind_to_interface
        enable_promiscuous if @promiscuous
        @open = true
        self
      rescue Errno::EPERM, Errno::EACCES => e
        raise PermissionError, "AF_PACKET needs root or CAP_NET_RAW: #{e.message}"
      end

      def recv
        ensure_open
        if @recv_timeout
          ready = IO.select([@socket], nil, nil, @recv_timeout)
          raise TimeoutError, "no frame within #{@recv_timeout}s" if ready.nil?
        end
        data, = @socket.recvfrom(65_535)
        CapturedFrame.new(data, Time.now)
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
    end
  end
end
