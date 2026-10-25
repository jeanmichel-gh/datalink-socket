# frozen_string_literal: true

require "datalink/backends/base"

module Datalink
  module Backends
    # Read frames from, and write frames to, a classic libpcap file
    # (the format Wireshark and tcpdump use). No privileges needed.
    #
    # Read a capture:
    #   r = PcapFile.new("capture.pcap", mode: :read).open
    #   loop { puts r.recv.frame } rescue Datalink::TimeoutError
    #
    # Record what you send:
    #   w = PcapFile.new("out.pcap", mode: :write).open
    #   w.send(frame); w.close
    #
    # Only the legacy pcap format (magic 0xa1b2c3d4) with link type
    # ETHERNET (1) is handled, which is all this library produces.
    class PcapFile < Base
      MAGIC = 0xa1b2c3d4
      MAGIC_SWAPPED = 0xd4c3b2a1
      LINKTYPE_ETHERNET = 1
      GLOBAL_HEADER_SIZE = 24
      RECORD_HEADER_SIZE = 16

      def initialize(path, mode: :read, recv_timeout: nil)
        super(path, recv_timeout: recv_timeout)
        @path = path
        @mode = mode
        raise ArgumentError, "mode must be :read or :write" unless %i[read write].include?(mode)
      end

      def open
        case @mode
        when :read  then open_for_read
        when :write then open_for_write
        end
        @open = true
        self
      end

      # Returns the next frame, or raises TimeoutError at end of file (so
      # callers can treat EOF and "nothing arrived" the same way a live
      # socket would).
      def recv
        ensure_open(:read)
        header = @io.read(RECORD_HEADER_SIZE)
        raise TimeoutError, "end of capture" if header.nil? || header.bytesize < RECORD_HEADER_SIZE

        ts_sec, ts_usec, incl_len, _orig_len = unpack_record_header(header)
        data = @io.read(incl_len)
        raise ParseError, "truncated record in #{@path}" if data.nil? || data.bytesize < incl_len

        CapturedFrame.new(data, Time.at(ts_sec, ts_usec))
      end

      def close
        @io&.close
        @open = false
      end

      private

      def open_for_read
        @io = File.open(@path, "rb")
        global = @io.read(GLOBAL_HEADER_SIZE)
        raise ParseError, "not a pcap file: #{@path}" if global.nil? || global.bytesize < GLOBAL_HEADER_SIZE

        magic = global[0, 4].unpack1("N")
        @swapped =
          case magic
          when MAGIC then false
          when MAGIC_SWAPPED then true
          else raise ParseError, "bad pcap magic in #{@path}"
          end
        linktype = read_u32(global[20, 4])
        unless linktype == LINKTYPE_ETHERNET
          raise ParseError, "unsupported link type #{linktype} in #{@path} (want Ethernet)"
        end
      end

      def open_for_write
        @io = File.open(@path, "wb")
        @swapped = false
        # Legacy global header: magic, version 2.4, zero zone/sigfigs,
        # snaplen 65535, Ethernet link type.
        @io.write([MAGIC, 2, 4, 0, 0, 65_535, LINKTYPE_ETHERNET].pack("NnnNNNN"))
      end

      def do_send(bytes)
        ensure_open(:write)
        now = Time.now
        @io.write([now.to_i, now.usec, bytes.bytesize, bytes.bytesize].pack("NNNN"))
        @io.write(bytes)
        bytes.bytesize
      end

      def unpack_record_header(header)
        if @swapped
          header.unpack("VVVV")
        else
          header.unpack("NNNN")
        end
      end

      def read_u32(bytes)
        @swapped ? bytes.unpack1("V") : bytes.unpack1("N")
      end

      def ensure_open(expected)
        raise Error, "backend not open" unless @open
        raise Error, "backend opened for #{@mode}, not #{expected}" unless @mode == expected
      end
    end
  end
end
