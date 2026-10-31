# frozen_string_literal: true

require_relative "../test_helper"

class TestLLC < Minitest::Test
  LLC = Datalink::LLC

  def test_encode_is_three_bytes
    llc = LLC.new(dsap: LLC::SAP_ISIS, ssap: LLC::SAP_ISIS)
    assert_equal "\xFE\xFE\x03".b, llc.encode
  end

  def test_wrap_and_parse_roundtrip
    llc = LLC.new(dsap: LLC::SAP_ISIS, ssap: LLC::SAP_ISIS)
    wrapped = llc.wrap("payload")
    header, rest = LLC.parse(wrapped)
    assert_equal llc, header
    assert_equal "payload", rest
  end

  def test_parse_reports_saps
    header, = LLC.parse("\xFE\xFE\x03rest".b)
    assert_equal 0xFE, header.dsap
    assert_equal 0xFE, header.ssap
    assert_equal LLC::CONTROL_UI, header.control
  end

  def test_parse_rejects_short
    assert_raises(Datalink::ParseError) { LLC.parse("\xFE\xFE".b) }
  end

  def test_parse_rejects_non_u_format
    # control 0x00 is an I-format frame, not supported
    assert_raises(Datalink::ParseError) { LLC.parse("\xFE\xFE\x00".b) }
  end

  def test_equality_and_hash
    a = LLC.new(dsap: 0xFE, ssap: 0xFE)
    b = LLC.new(dsap: 0xFE, ssap: 0xFE)
    assert_equal a, b
    assert_equal a.hash, b.hash
  end
end
