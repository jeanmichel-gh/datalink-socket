require 'ethernet'
require 'ipaddr'

class Arp
  include Args

  HwSrc    = Class.new(Ethernet::Address)
  HwTgt    = Class.new(Ethernet::Address)
  ProtoSrc = Class.new(IPAddr)
  ProtoTgt = Class.new(IPAddr)

  attr_reader :hw_src, :hw_tgt, :proto_src, :proto_tgt, :opcode

  def initialize(arg={})
    if arg.is_a?(Hash)
      @hw_tgt = HwTgt.new
      @opcode, @hw_src, @proto_src, @proto_tgt = 1, nil, nil, nil
      set arg
    elsif arg.is_a?(String)
      parse arg
    else
    end
  end

  def encode
    s=[]
    hw_src = @hw_src.encode
    proto_src = @proto_src.hton
    hw_tgt = @hw_tgt.encode
    proto_tgt = @proto_tgt.hton
    s << eth_hdr
    s << [1,0x0800, 6, 4, @opcode, hw_src, proto_src, hw_tgt, proto_tgt].pack("nnCCn"+"a6a4"*2)
    s.join
  end

  def parse(s)
    # p s.unpack('H*')
    # p s.size
    s.slice!(0,14) if s.size>32
    htype, ptype, hlen, plen, opcode = s.unpack('nnccn')
    # p htype
    # p ptype
    hw_src, proto_src, hw_tgt, proto_tgt = s[8..-1].unpack("a#{hlen}a#{plen}"*2)
    raise RuntimeError, "Unsupported Hardware Type" unless htype == 1 && ptype == 0x0800
    @hw_src = HwSrc.new(hw_src)
    @hw_tgt = HwTgt.new(hw_tgt)
    @proto_src = ProtoSrc.ntop(proto_src)
    @proto_tgt = ProtoTgt.ntop(proto_tgt)
    @opcode = opcode
  end

  def to_s
    case @opcode
    when 1 ; "ARP, Request who-has #{@proto_tgt} tell #{@proto_src}"
    when 2 ; "ARP, Reply #{@proto_src} is-at #{@hw_src}"
    end
  end
  
  def reply(hw_src)
    self.class.new_reply :hw_src=> hw_src, :proto_src=> "#{@proto_tgt}",
                   :hw_tgt => "#{@hw_src}", :proto_tgt => "#{@proto_src}"
  end
  
  class << self
    def Arp.new_request(arg={})
      if arg.is_a?(Hash)
        arg[:opcode]=1
        new arg
      end
    end
    def Arp.new_reply(arg={})
      if arg.is_a?(Hash)
        arg[:opcode]=2
        new arg
      end
    end
  end

  private

  def eth_hdr
    src = @hw_src.to_s
    dst = @opcode == 1 ? 'ffff.ffff.ffff' : @hw_tgt.to_s
    f = ::Ethernet::Frame.new :dst=> dst, :src=> src
    f.encode(::Ethernet::Type::ETH_ARP)
  end
end
