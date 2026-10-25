# frozen_string_literal: true

require "datalink/error"

module Datalink
  # An IEEE 802 MAC address: six octets, immutable, comparable.
  #
  # Accepts the common text forms and raw bytes:
  #   MAC.new("00:11:22:33:44:55")   # colon
  #   MAC.new("00-11-22-33-44-55")   # dash
  #   MAC.new("0011.2233.4455")      # dotted hex (Cisco style)
  #   MAC.new("001122334455")        # bare hex
  #   MAC.new("\x00\x11\x22\x33\x44\x55".b)  # 6 raw bytes
  #   MAC.new([0, 17, 34, 51, 68, 85])       # array of octets
  #   MAC.new(other_mac)             # copy
  #
  # Short octets are accepted in text forms ("1:2:3:4:5:6"), matching the
  # old library. Each octet must still fit in a byte.
  class MAC
    LENGTH = 6

    # @return [Array<Integer>] the six octets, frozen
    attr_reader :octets

    class << self
      # The broadcast address ff:ff:ff:ff:ff:ff.
      def broadcast
        @broadcast ||= new([0xff] * LENGTH).freeze
      end

      # The all-zero address 00:00:00:00:00:00.
      def zero
        @zero ||= new([0] * LENGTH).freeze
      end

      # A random locally-administered unicast address. Good for
      # masquerade: the second-least-significant bit of the first octet
      # is set (locally administered) and the least-significant bit is
      # cleared (unicast).
      def random
        first = (rand(256) & 0xfc) | 0x02
        new([first, *Array.new(LENGTH - 1) { rand(256) }])
      end

      # Parse from raw bytes without guessing the format. Strict 6 bytes.
      def from_bytes(str)
        b = str.b
        raise AddressError, "MAC needs #{LENGTH} bytes, got #{b.bytesize}" unless b.bytesize == LENGTH

        new(b.unpack("C#{LENGTH}"))
      end
    end

    def initialize(arg)
      @octets =
        case arg
        when MAC          then arg.octets.dup
        when Array        then parse_array(arg)
        when String       then parse_string(arg)
        else
          raise AddressError, "cannot build a MAC from #{arg.class}: #{arg.inspect}"
        end
      @octets.freeze
      freeze
    end

    # Six bytes, network order, for putting on the wire.
    # @return [String] binary, ASCII-8BIT
    def encode
      @octets.pack("C#{LENGTH}")
    end
    alias to_bytes encode

    # @return [String] e.g. "00:11:22:33:44:55" (or with a chosen delimiter)
    def to_s(delimiter = ":")
      case delimiter
      when ".", "dotted"
        encode.unpack("n3").map { |w| format("%04x", w) }.join(".")
      else
        @octets.map { |o| format("%02x", o) }.join(delimiter)
      end
    end

    def to_shex
      @octets.map { |o| format("%02x", o) }.join
    end

    def inspect
      "#<Datalink::MAC #{self}>"
    end

    def ==(other)
      other.is_a?(MAC) && other.octets == @octets
    end
    alias eql? ==

    def hash
      @octets.hash
    end

    def broadcast?
      @octets.all? { |o| o == 0xff }
    end

    def zero?
      @octets.all?(&:zero?)
    end

    # Group bit (least-significant bit of the first octet). Set means a
    # multicast address; broadcast is a special case of multicast.
    def multicast?
      @octets[0].odd?
    end

    def unicast?
      !multicast?
    end

    # Locally-administered bit (bit 1 of the first octet).
    def local?
      @octets[0].anybits?(0x02)
    end

    def global?
      !local?
    end

    # Organizationally Unique Identifier: the first three octets.
    def oui
      @octets[0, 3].map { |o| format("%02x", o) }.join(":")
    end

    private

    def parse_array(arr)
      raise AddressError, "MAC needs #{LENGTH} octets, got #{arr.size}" unless arr.size == LENGTH

      arr.map do |o|
        o = Integer(o)
        raise AddressError, "octet out of range: #{o}" unless (0..255).cover?(o)

        o
      end
    end

    def parse_string(str)
      # Raw 6-byte binary (no separators, not hex text).
      return str.unpack("C#{LENGTH}") if str.bytesize == LENGTH && !printable_hex?(str)

      cleaned = str.delete(":.\\-").strip
      unless cleaned.match?(/\A\h+\z/) && !cleaned.empty?
        raise AddressError, "not a MAC address: #{str.inspect}"
      end

      if str.include?(":") || str.include?("-")
        parts = str.split(/[:-]/)
        raise AddressError, "MAC needs #{LENGTH} groups: #{str.inspect}" unless parts.size == LENGTH

        parts.map { |p| hex_octet(p, str) }
      else
        # Bare or dotted hex: pad each octet to two nibbles.
        raise AddressError, "odd hex length: #{str.inspect}" if cleaned.size.odd?
        raise AddressError, "MAC needs #{LENGTH * 2} hex digits: #{str.inspect}" unless cleaned.size == LENGTH * 2

        cleaned.scan(/../).map { |p| p.to_i(16) }
      end
    end

    def hex_octet(part, original)
      raise AddressError, "empty octet in #{original.inspect}" if part.empty?
      raise AddressError, "octet too long in #{original.inspect}: #{part.inspect}" if part.size > 2

      part.to_i(16)
    end

    # A 6-byte string that is all hex text (like "001122") should be
    # treated as text, not raw bytes.
    def printable_hex?(str)
      str.match?(/\A\h{6}\z/)
    end
  end
end
