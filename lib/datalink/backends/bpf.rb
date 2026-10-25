# frozen_string_literal: true

require "datalink/backends/base"

module Datalink
  module Backends
    # BPF backend for macOS and the BSDs, over /dev/bpfN.
    #
    # Needs root (or group/ACL access to the bpf devices). Opens the
    # first free /dev/bpf device, binds it to the interface, sets
    # immediate mode, and reads frames out of the BPF buffer, honoring
    # the per-record bh_hdrlen and BPF_WORDALIGN padding.
    #
    # Modernized from the original: timeouts via IO.select, the BPF read
    # buffer size is queried once and reused, the receive queue is drained
    # per read, and BIOCSHDRCMPLT is set so the source MAC we put in a
    # frame is sent as-is (the kernel does not overwrite it) -- essential
    # for spoofing.
    class BPF < Base
      # ioctl request codes (same on the Darwin/BSD ABIs this targets).
      BIOCSETIF     = 0x8020426c
      BIOCIMMEDIATE = 0x80044270
      BIOCGBLEN     = 0x40044266
      BIOCSBLEN     = 0xc0044266
      BIOCPROMISC   = 0x20004269
      BIOCSHDRCMPLT = 0x80044275
      BIOCSSEESENT  = 0x80044277
      BIOCSRTIMEOUT = 0x8008426d

      MAX_BPF_DEVICES = 256

      def self.available?
        os = RUBY_PLATFORM
        os.include?("darwin") || os.include?("bsd")
      end

      def initialize(interface, recv_timeout: nil, promiscuous: false, see_sent: false)
        super(interface, recv_timeout: recv_timeout)
        @promiscuous = promiscuous
        @see_sent = see_sent
        @queue = []
      end

      def open
        open_bpf_device
        configure
        @open = true
        self
      rescue Errno::EPERM, Errno::EACCES => e
        raise PermissionError, "BPF needs root or access to /dev/bpf*: #{e.message}"
      end

      def recv
        ensure_open
        return @queue.shift unless @queue.empty?

        if @recv_timeout
          ready = IO.select([@bpf], nil, nil, @recv_timeout)
          raise TimeoutError, "no frame within #{@recv_timeout}s" if ready.nil?
        end
        drain_buffer
        retry_recv
      end

      def close
        @bpf&.close
        @open = false
      end

      private

      def retry_recv
        return @queue.shift unless @queue.empty?

        # Buffer held only padding; try once more.
        recv
      end

      def do_send(bytes)
        ensure_open
        @bpf.write_nonblock(bytes)
      end

      def open_bpf_device
        0.upto(MAX_BPF_DEVICES - 1) do |n|
          @bpf = File.open("/dev/bpf#{n}", "r+b")
          return
        rescue Errno::EBUSY
          next
        rescue Errno::ENOENT
          break
        end
        raise Error, "no free /dev/bpf device found"
      end

      def configure
        @bpf.ioctl(BIOCSETIF, [@interface].pack("a32"))
        @bpf.ioctl(BIOCIMMEDIATE, [1].pack("I"))
        @bpf.ioctl(BIOCSHDRCMPLT, [1].pack("I")) # we supply the source MAC
        @bpf.ioctl(BIOCSSEESENT, [@see_sent ? 1 : 0].pack("I"))
        @bpf.ioctl(BIOCPROMISC, "") if @promiscuous
        buf = [0].pack("i")
        @bpf.ioctl(BIOCGBLEN, buf)
        @buffer_size = buf.unpack1("i")
      end

      # Read one bufferful and split it into frames. A BPF buffer holds
      # several records, each a bpf_hdr followed by the captured bytes,
      # padded to a 4-byte boundary.
      def drain_buffer
        raw = @bpf.sysread(@buffer_size)
        offset = 0
        while offset < raw.bytesize
          # struct bpf_hdr (Darwin/BSD): the fields we need are the
          # captured length (bh_caplen) at +8 and the header length
          # (bh_hdrlen) at +16. Timestamp is at the start.
          ts_sec  = raw[offset, 4].unpack1("l!")
          ts_usec = raw[offset + 4, 4].unpack1("l!")
          caplen  = raw[offset + 8, 4].unpack1("L")
          hdrlen  = raw[offset + 16, 2].unpack1("v")

          frame_start = offset + hdrlen
          bytes = raw[frame_start, caplen]
          @queue << CapturedFrame.new(bytes, Time.at(ts_sec, ts_usec)) if bytes && bytes.bytesize == caplen

          offset = bpf_wordalign(frame_start + caplen)
        end
      end

      # BPF_WORDALIGN: round up to the next 4-byte boundary.
      def bpf_wordalign(n)
        (n + 3) & ~3
      end

      def ensure_open
        raise Error, "backend not open" unless @open
      end
    end
  end
end
