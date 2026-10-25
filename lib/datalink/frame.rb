# frozen_string_literal: true

require "datalink/error"
require "datalink/mac"
require "datalink/ether_type"

module Datalink
  # An Ethernet II frame: destination MAC, source MAC, EtherType, and a
  # payload of raw bytes or any object that responds to #encode.
  #
  # Build one:
  #   Frame.new(dst: "ff:ff:ff:ff:ff:ff", src: my_mac,
  #             ether_type: Datalink::EtherType::ARP, payload: arp)
  #
  # Parse bytes off the wire:
  #   frame = Frame.parse(bytes)
  #   frame.src          #=> Datalink::MAC
  #   frame.ether_type   #=> 0x0800
  #   frame.payload      #=> String (the bytes after the header)
  #
  # 802.1Q VLAN tags are recognized on parse: #vlan_id and #vlan? are
  # populated and #ether_type reports the inner type.
  class Frame
    HEADER_SIZE = 14
    VLAN_TAG_SIZE = 4
    # Minimum payload so the frame reaches the 60-byte (pre-FCS) floor.
    MIN_PAYLOAD = 46

    attr_accessor :dst, :src, :ether_type
    attr_reader :payload, :vlan_id, :vlan_priority

    def initialize(dst: MAC.zero, src: MAC.zero, ether_type: 0, payload: nil,
                   vlan_id: nil, vlan_priority: 0)
      self.dst = dst
      self.src = src
      @ether_type = ether_type
      self.payload = payload
      @vlan_id = vlan_id
      @vlan_priority = vlan_priority
    end

    # Coerce strings into MAC objects on assignment, so both
    # Frame.new(dst: "..:..") and Frame.new(dst: mac) work.
    def dst=(value)
      @dst = value.is_a?(MAC) ? value : MAC.new(value)
    end

    def src=(value)
      @src = value.is_a?(MAC) ? value : MAC.new(value)
    end

    def payload=(value)
      @payload =
        if value.nil?            then ""
        elsif value.respond_to?(:encode) && !value.is_a?(String) then value.encode
        else value.b
        end
    end

    def vlan?
      !@vlan_id.nil?
    end

    # The full frame as bytes, ready to put on the wire. Does not add the
    # FCS (the kernel/NIC appends that) and does not pad to the 60-byte
    # minimum unless +pad:+ is true.
    def encode(pad: false)
      out = +""
      out << @dst.encode
      out << @src.encode
      if vlan?
        out << [EtherType::VLAN].pack("n")
        tci = ((@vlan_priority & 0x7) << 13) | (@vlan_id & 0x0fff)
        out << [tci].pack("n")
      end
      out << [@ether_type].pack("n")
      body = @payload.dup
      body << ("\x00" * (MIN_PAYLOAD - body.bytesize)) if pad && body.bytesize < MIN_PAYLOAD
      out << body
      out
    end

    # Parse raw bytes into a Frame. Raises ParseError if too short.
    def self.parse(bytes)
      b = bytes.b
      raise ParseError, "frame too short: #{b.bytesize} bytes" if b.bytesize < HEADER_SIZE

      dst = MAC.from_bytes(b[0, 6])
      src = MAC.from_bytes(b[6, 6])
      type = b[12, 2].unpack1("n")

      vlan_id = nil
      vlan_priority = 0
      offset = HEADER_SIZE
      if type == EtherType::VLAN
        raise ParseError, "truncated VLAN tag" if b.bytesize < HEADER_SIZE + VLAN_TAG_SIZE

        tci = b[14, 2].unpack1("n")
        vlan_priority = (tci >> 13) & 0x7
        vlan_id = tci & 0x0fff
        type = b[16, 2].unpack1("n")
        offset = HEADER_SIZE + VLAN_TAG_SIZE
      end

      new(dst: dst, src: src, ether_type: type,
          payload: b[offset..] || "",
          vlan_id: vlan_id, vlan_priority: vlan_priority)
    end

    # IEEE 802.3 length-encapsulated frame (type field < 0x0600).
    def ieee_802_3?
      @ether_type < 0x0600
    end

    # Ethernet II frame (type field >= 0x0600).
    def ethernet_v2?
      !ieee_802_3?
    end

    def ether_type_name
      EtherType.name(@ether_type)
    end

    def to_s
      s = "#{src} > #{dst}"
      s << " vlan #{vlan_id}" if vlan?
      s << " #{ether_type_name} len #{payload.bytesize}"
      s
    end

    def to_shex
      encode.unpack1("H*")
    end
  end
end
