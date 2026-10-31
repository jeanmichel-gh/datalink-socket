# frozen_string_literal: true

require "datalink/error"

module Datalink
  # An IEEE 802.2 LLC header: destination SAP, source SAP, and a control
  # field, in front of the upper-layer data inside an 802.3 frame.
  #
  # Only the U-format (unnumbered, one-byte control) is modeled, which is
  # what connectionless link-layer protocols use. The common case is UI
  # (control 0x03). The I and S formats, with a two-byte control, are not
  # modeled.
  #
  #   llc = Datalink::LLC.new(dsap: Datalink::LLC::SAP_ISIS,
  #                           ssap: Datalink::LLC::SAP_ISIS)
  #   bytes = llc.wrap(pdu)           # header + pdu
  #   header, pdu = Datalink::LLC.parse(bytes)
  #
  # This is link-layer plumbing, shared by IS-IS, STP, CDP and others.
  # Which SAP marks which protocol is the caller's decision.
  class LLC
    SIZE = 3
    CONTROL_UI = 0x03

    # A few registered SAP values, for convenience.
    SAP_ISIS   = 0xFE
    SAP_SNAP   = 0xAA
    SAP_STP    = 0x42
    SAP_GLOBAL = 0xFF
    SAP_NULL   = 0x00

    attr_reader :dsap, :ssap, :control

    def initialize(dsap:, ssap:, control: CONTROL_UI)
      @dsap = dsap
      @ssap = ssap
      @control = control
      freeze
    end

    # The 3-byte header.
    def encode
      [@dsap, @ssap, @control].pack("C3")
    end

    # Header followed by the upper-layer data.
    def wrap(sdu)
      encode + sdu.b
    end

    # Parse a U-format LLC header. Returns [llc, remaining_bytes]. Raises
    # ParseError on a short header or a non-U-format control field.
    def self.parse(bytes)
      b = bytes.b
      raise ParseError, "short LLC header: #{b.bytesize} bytes" if b.bytesize < SIZE

      dsap, ssap, control = b[0, SIZE].unpack("C3")
      unless (control & 0x3) == 0x3
        raise ParseError, format("only U-format LLC is supported (control=0x%02x)", control)
      end

      [new(dsap: dsap, ssap: ssap, control: control), b[SIZE..] || ""]
    end

    def ==(other)
      other.is_a?(LLC) && other.dsap == @dsap && other.ssap == @ssap && other.control == @control
    end
    alias eql? ==

    def hash
      [@dsap, @ssap, @control].hash
    end

    def to_s
      format("LLC dsap=0x%02x ssap=0x%02x control=0x%02x", @dsap, @ssap, @control)
    end
  end
end
