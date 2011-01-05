#
# Copyright (c) 2011 Jean-Michel Esnault. Released under the same license as Ruby
# 

require 'ruby-ext'
require 'dl_socket'
require 'rubygems'
#--
# require 'oui'
#++

module Ethernet
  class Socket < Datalink::Socket
    case `uname`.chomp.downcase
    when 'darwin'
      def recv(*args)
        eth_frame = super
        eth_type = eth_frame.slice(12,2).unpack('n')[0]
        [eth_frame, eth_type]
      end
    when 'linux'
      def recv(*args)
        eth_frame, eth_type, _ = super
        [eth_frame, eth_type]
      end
    end
  end
  
  module Type
    ETH_IPv4        = 0x0800
    ETH_ARP         = 0x0806
    ETH_RARP        = 0x8035
    ETH_Ethertalk   = 0x809B
    ETH_AARP        = 0x80F3
    ETH_IEEE_802_1Q = 0x8100
    ETH_IPv6        = 0x86DD
    def self.to_s(type)
      case type
      when ETH_IPv4        ; 'IPv4'
      when ETH_IPv6        ; 'IPv6'
      when ETH_ARP         ; 'ARP'
      when ETH_RARP        ; 'RARP'
      when ETH_Ethertalk   ; 'AppleTalk Ethertalk'
      when ETH_AARP        ; 'AppleTalk Address Resolution Protocol'
      when ETH_IEEE_802_1Q ; 'IEEE_802_1Q'
      else
        format("0x%04x",type)
      end
    end

  end
  class Address
    attr_reader :mac

    def initialize(arg=nil)
      if arg.is_a?(String) and arg.size==6
        parse(arg)
      elsif arg.is_a?(String) and arg.size==14
        parse [arg.split('.').join].pack('H*')
      elsif arg.is_a?(String)
        @mac = arg.split(/[-:]/).collect { |n| n.to_i(16) }
      elsif arg.is_a?(String) and size==14
      elsif arg.kind_of?(self.class)
        parse arg.encode
      elsif arg.kind_of?(self.class)
        parse arg.encode
      elsif ! arg
        @mac = [0,0,0,0,0,0]
      else
        raise ArgumentError, "Argument error: #{self.class} #{arg.inspect}"
      end
    end

    def to_s(delim=":")
      case delim
      when ':'
        (format (["%02x"]*6).join(delim), *@mac)
      when '.'
        (format (["%04x"]*3).join(delim), *(@mac.pack('C6').unpack('n3')))
      end
    end

    #--
    # def to_s_oui
    #   comp_id = Ethernet::OUI.company_id_from_arr(@mac[0..2])
    #   if comp_id == 'Unknown'
    #     to_s.downcase
    #   else
    #     s = []
    #     s << comp_id
    #     s <<  (format (["%02x"]*3).join(":"), *@mac[3..5])
    #     s.join('_')
    #   end
    # end
    #++

    def encode
      @mac.pack('C*')
    end
    
    def to_hash
      to_s
    end

    private

    def parse(s)
      @mac = s.unpack('C6')
    end
  end

  include Type

  def self.packet_factory(frame, ether_type, time)
    s = frame.dup
    case ether_type
    when IPv4  ; puts "IPv4:"
    when IPv6  ; puts "IPv6:"
    when ARP   ; puts "ARP:"
    when RARP  ; puts "RARP:"
    else
      puts "Ether_type: #{ether_type}:"
    end
    puts s.unpack('H*')
  end

  class Frame
    include Args
    Src = Class.new(Address)
    Dst = Class.new(Address)
    attr_reader :src, :dst, :ether_type, :payload
    attr_writer_delegate :src, :dst
    def initialize(arg={})
      if arg.is_a?(Hash)
        @src = Src.new
        @dst = Dst.new
        @ether_type=0
        set(arg)
      elsif arg.is_a?(String)
        parse arg
      else
        raise ArgumentError, "Invalid argument :#{arg.inspect}"
      end
    end
    def encode(ether_type=@ether_type, payload=nil)
      @ether_type = ether_type if ether_type
      @payload = payload if payload
      frame = []
      frame << @dst.encode
      frame << @src.encode
      frame << [ether_type].pack('n')
      if @payload
        if @payload.respond_to?(:encode)
          frame << @payload.encode if @payload.respond_to?(:encode)
        else
          frame << @payload
        end
      end
      frame.join
    end
    def parse(s)
      self.dst = s.slice!(0,6)
      self.src = s.slice!(0,6)
      @ether_type = s.slice!(0,2).unpack('n')[0]
      @payload = s
    end
    def ieee_802_3?
      type? == :ieee_802_3
    end
    def ethernet_v2?
      type? == :ethernet_v2
    end
    def type?
      if @ether_type < 0x600
        :ieee_802_3
      else
        :ethernet_v2
      end
    end
  end
end
