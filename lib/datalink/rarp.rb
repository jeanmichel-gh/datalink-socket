# frozen_string_literal: true

require "ipaddr"
require "datalink/error"
require "datalink/mac"
require "datalink/ether_type"
require "datalink/frame"

module Datalink
  # A RARP packet (RFC 903): Reverse ARP. Where ARP asks "what MAC owns
  # this IP?", RARP asks "what IP belongs to this MAC?" A diskless host
  # historically used it at boot to learn its own address from a RARP
  # server.
  #
  # The wire layout is identical to ARP (RFC 826); only the EtherType
  # (0x8035) and the opcodes differ:
  #   3 = request  (reverse request)
  #   4 = reply    (reverse reply)
  #
  #   # A host asking "what is my IP?" knows only its own MAC:
  #   Datalink::RARP.request(sender_mac: my_mac, target_mac: my_mac)  # => Frame
  #
  #   # A server answering, filling in the IP it assigns:
  #   Datalink::RARP.reply(sender_mac: server_mac, sender_ip: server_ip,
  #                        target_mac: client_mac, target_ip: assigned_ip)
  class RARP
    HTYPE_ETHERNET = 1
    PTYPE_IPV4     = EtherType::IPV4
    HLEN_ETHERNET  = 6
    PLEN_IPV4      = 4

    REQUEST = 3
    REPLY   = 4

    OPCODE_NAMES = { REQUEST => "request", REPLY => "reply" }.freeze
    SIZE = 28

    attr_reader :opcode, :sender_mac, :sender_ip, :target_mac, :target_ip
    attr_reader :htype, :ptype, :hlen, :plen

    def initialize(opcode:, sender_mac:, target_mac:,
                   sender_ip: "0.0.0.0", target_ip: "0.0.0.0",
                   htype: HTYPE_ETHERNET, ptype: PTYPE_IPV4,
                   hlen: HLEN_ETHERNET, plen: PLEN_IPV4)
      @opcode = opcode
      @sender_mac = coerce_mac(sender_mac)
      @target_mac = coerce_mac(target_mac)
      @sender_ip = coerce_ip(sender_ip)
      @target_ip = coerce_ip(target_ip)
      @htype = htype
      @ptype = ptype
      @hlen = hlen
      @plen = plen
    end

    # The 28-byte RARP payload (no Ethernet header).
    def encode
      [
        @htype, @ptype, @hlen, @plen, @opcode,
        @sender_mac.encode, @sender_ip.hton,
        @target_mac.encode, @target_ip.hton
      ].pack("nnCCna6a4a6a4")
    end

    def self.parse(bytes)
      b = bytes.b
      b = b[Frame::HEADER_SIZE..] if b.bytesize >= Frame::HEADER_SIZE + SIZE
      raise ParseError, "RARP packet too short: #{b.bytesize} bytes" if b.nil? || b.bytesize < SIZE

      htype, ptype, hlen, plen, opcode = b.unpack("nnCCn")
      unless htype == HTYPE_ETHERNET && ptype == PTYPE_IPV4
        raise ParseError,
              format("unsupported RARP htype=0x%04x ptype=0x%04x", htype, ptype)
      end

      sender_mac, sender_ip, target_mac, target_ip = b[8, 20].unpack("a6a4a6a4")
      new(
        opcode: opcode,
        sender_mac: MAC.from_bytes(sender_mac),
        sender_ip: IPAddr.new_ntoh(sender_ip),
        target_mac: MAC.from_bytes(target_mac),
        target_ip: IPAddr.new_ntoh(target_ip),
        htype: htype, ptype: ptype, hlen: hlen, plen: plen
      )
    end

    # A RARP request is broadcast; a reply is unicast to the target MAC.
    def to_frame(dst: nil)
      dst ||= request? ? MAC.broadcast : @target_mac
      Frame.new(dst: dst, src: @sender_mac, ether_type: EtherType::RARP, payload: encode)
    end

    def request?
      @opcode == REQUEST
    end

    def reply?
      @opcode == REPLY
    end

    def opcode_name
      OPCODE_NAMES[@opcode] || "opcode #{@opcode}"
    end

    # Build the reply that assigns +assigned_ip+ to the host that asked,
    # answering as +server_mac+ / +server_ip+.
    def build_reply(server_mac:, server_ip:, assigned_ip:)
      raise Error, "can only reply to a request" unless request?

      self.class.new(
        opcode: REPLY,
        sender_mac: server_mac, sender_ip: server_ip,
        target_mac: @target_mac, target_ip: assigned_ip
      )
    end

    def to_s
      case @opcode
      when REQUEST then "RARP request: who-is #{@target_mac} (tell #{@sender_mac})"
      when REPLY   then "RARP reply: #{@target_mac} is-at #{@target_ip}"
      else "RARP #{opcode_name}"
      end
    end

    def to_shex
      encode.unpack1("H*")
    end

    class << self
      def request(sender_mac:, target_mac:, sender_ip: "0.0.0.0", target_ip: "0.0.0.0")
        new(opcode: REQUEST, sender_mac: sender_mac, target_mac: target_mac,
            sender_ip: sender_ip, target_ip: target_ip).to_frame
      end

      def reply(sender_mac:, sender_ip:, target_mac:, target_ip:)
        new(opcode: REPLY, sender_mac: sender_mac, sender_ip: sender_ip,
            target_mac: target_mac, target_ip: target_ip).to_frame
      end

      def new_request(**kwargs)
        new(opcode: REQUEST, **kwargs)
      end

      def new_reply(**kwargs)
        new(opcode: REPLY, **kwargs)
      end
    end

    private

    def coerce_mac(value)
      value.is_a?(MAC) ? value : MAC.new(value)
    end

    def coerce_ip(value)
      case value
      when IPAddr then value
      when String then IPAddr.new(value)
      else raise AddressError, "cannot build an IP from #{value.inspect}"
      end
    end
  end
end
