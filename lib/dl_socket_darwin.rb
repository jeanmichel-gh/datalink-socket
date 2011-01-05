module Datalink

  BIOCGBLEN      =   0x40044266
  BIOCSBLEN      =   0xc0044266
  BIOCSETF       =   0x80084267
  BIOCFLUSH      =   0x20004268
  BIOCPROMISC    =   0x20004269
  BIOCGDLT       =   0x4004426a
  BIOCGETIF      =   0x4020426b
  BIOCSETIF      =   0x8020426c
  BIOCSRTIMEOUT  =   0x8008426d
  BIOCGRTIMEOUT  =   0x4008426e
  BIOCGSTATS     =   0x4008426f
  BIOCIMMEDIATE  =   0x80044270
  BIOCVERSION    =   0x40044271
  BIOCGRSIG      =   0x40044272
  BIOCSRSIG      =   0x80044273
  BIOCGHDRCMPLT  =   0x40044274
  BIOCSHDRCMPLT  =   0x80044275
  BIOCGSEESENT   =   0x40044276
  BIOCSSEESENT   =   0x80044277
  BIOCSDLT       =   0x80044278
  BIOCGDLTLIST   =   0xc00c4279

  class Socket

    attr_accessor :if_name
    attr_reader :device_name, :device

    def initialize(if_name)
      @if_name = if_name
    end

    def open(if_name=@if_name)
      num=0
      @if_name = if_name
      begin
        bpf_name = "/dev/bpf#{num}"
        @file_handle = File.open(bpf_name, "w+")
      rescue => error
        if num < 30 and not defined?(@file_handle)
          num +=1
          retry
        else
          raise RuntimeError, "could not open #{bpf_name}: #{error}"
        end
      end

      @file_handle_name = bpf_name
      @file_handle.ioctl(BIOCSETIF, [@if_name].pack("a#{@if_name.size+1}"))
      @file_handle.ioctl(BIOCIMMEDIATE, [1].pack('I'))
      @file_handle.ioctl(BIOCGHDRCMPLT, [0].pack('N'))
      buf = [0].pack('i')
      @file_handle.ioctl(BIOCGBLEN, buf)
      @buf_size = buf.unpack('i')[0]
      timeout = [5,0].pack('LL')
      @file_handle.ioctl(BIOCSRTIMEOUT, timeout)
      self
    end

    def send(obj)
      @file_handle.write_nonblock(obj.respond_to?(:encode) ? obj.encode : obj)
    end

    def recv
      __recv
    end

    def close
      @file_handle.close
    end

    private

    def sysread_nb
      buf=''
      @file_handle.sysread(@buf_size, buf)
      buf
    end

    def sysread
      begin
        buf = sysread_nb
        return buf
      rescue EOFError, Errno::EAGAIN => e
        sleep(0.25)
        retry
      end
    end

    def __recv
      @recvQueue     ||=[]
      @packet_size   ||= lambda { |n| n+3 & ~3 }
      @header_decode ||= lambda { |hdr|
        datalen = hdr.slice(12,4).unpack('L')[0]
        hdrlen  = hdr.slice(16,2).unpack('v')[0]
        size    = @packet_size.call(datalen+hdrlen)
        [size, hdrlen]
      }
      if @recvQueue.empty?
        bpf_frames = sysread
        while bpf_frames.size>0
          size, hdrlen = @header_decode.call(bpf_frames)
          @recvQueue << bpf_frames.slice!(0,size)[hdrlen..-1]
        end
        __recv
      else
        @recvQueue.shift
      end
    end
  end
end

