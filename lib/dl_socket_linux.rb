require 'socket'

module Datalink
  class Socket < ::Socket

    IFF_UP         =  0x0001
    IFF_BROADCAST  =  0x0002
    IFF_DEBUG      =  0x0004
    IFF_LOOPBACK   =  0x0008
    IFF_P2P        =  0x0010
    IFF_NOTRAILERS =  0x0020
    IFF_RUNNING    =  0x0040
    IFF_NOARP      =  0x0080
    IFF_PROMISC    =  0x0100
    IFF_ALLMULTI   =  0x0200
    IFF_MASTER     =  0x0400
    IFF_SLAVE      =  0x0800
    IFF_MULTICAST  =  0x1000
    SIOCGIFINDEX   =  0x8933
    SIOCGIFFLAGS   =  0x8913
    SIOCSIFFLAGS   =  0x8914
    PF_PACKET      =  17
    AF_PACKET      =  PF_PACKET
    IFNAMSIZ       =  16

    def flags
      read_flags
    end
    self.class.constants.reject { |c| !( c =~/^IFF_/) }.collect { |f| f.to_s.split('_')[1].downcase}.each do |f|
      define_method("#{f}?") do
        flags & self.class.const_get("IFF_#{f.upcase}") > 0
      end
      define_method("set_#{f}") do
        flags = read_flags
        flags |= self.class.const_get("IFF_#{f.upcase}")
        write_flags(flags) 
      end
      define_method("unset_#{f}") do
        flags = read_flags
        flags &= ~self.class.const_get("IFF_#{f.upcase}")
        write_flags(flags) 
      end
    end

    def initialize(if_name, proto=0x003)
      @if_name = if_name
      super(PF_PACKET, Socket::SOCK_RAW, proto)
      ifreq = [if_name.dup].pack 'a32'
      ioctl(SIOCGIFINDEX, ifreq)
      bind [AF_PACKET].pack('s') + [proto].pack('n') + ifreq[16..20]+ ("\x00" * 12)
    end

    def recv
      data, from = recvfrom(2048)
      ether_type = data[12,2].unpack('n')[0]
      [data, ether_type, Time.now]
    end

    def send(obj)
      if obj.respond_to?(:encode)
        super(obj.encode,0)
      else
        super(obj,0)
      end
    end

    def open
    end

    private

    def read_flags
      ifreq = [@if_name.dup].pack "a#{IFNAMSIZ}"
      ioctl(SIOCGIFFLAGS,ifreq)
      ifreq[IFNAMSIZ,2].unpack('s')[0]
    end

    def write_flags(flags)
      ifreq = [@if_name.dup].pack("a#{IFNAMSIZ}") + [flags].pack('s')
      ioctl(SIOCSIFFLAGS,ifreq)
    end
  end
end
