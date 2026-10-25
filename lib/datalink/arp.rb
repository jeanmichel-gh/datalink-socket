# frozen_string_literal: true

require "ipaddr"
require "datalink/error"
require "datalink/mac"
require "datalink/ether_type"
require "datalink/frame"

module Datalink
  # An ARP packet (RFC 826) for IPv4-over-Ethernet, the common case.
  #
  # ARP maps a protocol address (IPv4) to a hardware address (MAC) on a
  # local segment. This class builds and parses the 28-byte ARP payload.
  # Wrapping it in an Ethernet frame is the Frame layer's job; the
  # convenience builders below return a ready-to-send Frame.
  #
  #   arp = Datalink::ARP.new(
  #     opcode: Datalink::ARP::REQUEST,
  #     sender_mac: "00:11:22:33:44:55", sender_ip: "192.168.1.10",
  #     target_ip: "192.168.1.1")
  #   frame = arp.to_frame            # Ethernet frame, broadcast
  #   sock.send(frame)
  #
  # Or the shortcuts:
  #   Datalink::ARP.request(sender_mac:, sender_ip:, target_ip:)   # => Frame
  #   Datalink::ARP.reply(sender_mac:, sender_ip:, target_mac:, target_ip:)
  class ARP
    HTYPE_ETHERNET = 1
    PTYPE_IPV4     = EtherType::IPV4
    HLEN_ETHERNET  = 6
    PLEN_IPV4      = 4

    REQUEST = 1
    REPLY   = 2

    OPCODE_NAMES = { REQUEST => "request", REPLY => "reply" }.freeze
    SIZE = 28

    attr_reader :opcode, :sender_mac, :sender_ip, :target_mac, :target_ip
    attr_reader :htype, :ptype, :hlen, :plen

    def initialize(opcode:, sender_mac:, sender_ip:, target_ip:,
                   target_mac: MAC.zero,
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

    # The 28-byte ARP payload (no Ethernet header).
    def encode
      [
        @htype, @ptype, @hlen, @plen, @opcode,
        @sender_mac.encode, @sender_ip.hton,
        @target_mac.encode, @target_ip.hton
      ].pack("nnCCna6a4a6a4")
    end

    # Parse a 28-byte ARP payload. Accepts a full Ethernet frame too and
    # strips the 14-byte header if present.
    def self.parse(bytes)
      b = bytes.b
      b = b[Frame::HEADER_SIZE..] if b.bytesize >= Frame::HEADER_SIZE + SIZE
      raise ParseError, "ARP packet too short: #{b.bytesize} bytes" if b.nil? || b.bytesize < SIZE

      htype, ptype, hlen, plen, opcode = b.unpack("nnCCn")
      unless htype == HTYPE_ETHERNET && ptype == PTYPE_IPV4
        raise ParseError,
              format("unsupported ARP htype=0x%04x ptype=0x%04x (want Ethernet/IPv4)", htype, ptype)
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

    # Wrap this ARP packet in an Ethernet frame. A request goes to the
    # broadcast address by default; a reply goes to the target's MAC.
    def to_frame(dst: nil)
      dst ||= request? ? MAC.broadcast : @target_mac
      Frame.new(dst: dst, src: @sender_mac, ether_type: EtherType::ARP, payload: encode)
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

    # Build the reply that answers this request, given the hardware
    # address of the host that owns the requested IP.
    def build_reply(sender_mac)
      raise Error, "can only reply to a request" unless request?

      self.class.new(
        opcode: REPLY,
        sender_mac: sender_mac, sender_ip: @target_ip,
        target_mac: @sender_mac, target_ip: @sender_ip
      )
    end

    def to_s
      case @opcode
      when REQUEST then "ARP request: who-has #{@target_ip} tell #{@sender_ip} (#{@sender_mac})"
      when REPLY   then "ARP reply: #{@sender_ip} is-at #{@sender_mac}"
      else "ARP #{opcode_name}: #{@sender_ip}/#{@sender_mac} -> #{@target_ip}/#{@target_mac}"
      end
    end

    def to_shex
      encode.unpack1("H*")
    end

    class << self
      # A request ("who has target_ip?"), wrapped in a broadcast frame.
      def request(sender_mac:, sender_ip:, target_ip:)
        new(opcode: REQUEST, sender_mac: sender_mac, sender_ip: sender_ip,
            target_ip: target_ip).to_frame
      end

      # A reply ("sender_ip is at sender_mac"), wrapped in a unicast frame.
      def reply(sender_mac:, sender_ip:, target_mac:, target_ip:)
        new(opcode: REPLY, sender_mac: sender_mac, sender_ip: sender_ip,
            target_mac: target_mac, target_ip: target_ip).to_frame
      end

      # Just the ARP object for a request (no frame), if you want to wrap
      # it yourself.
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
