# frozen_string_literal: true

require_relative "../test_helper"

class TestMAC < Minitest::Test
  MAC = Datalink::MAC

  def test_parses_colon_form
    assert_equal "00:11:22:33:44:55", MAC.new("00:11:22:33:44:55").to_s
  end

  def test_parses_short_octets
    assert_equal "01:02:03:04:05:06", MAC.new("1:2:3:4:5:6").to_s
    assert_equal "0a:0b:0c:0d:0e:0f", MAC.new("a:b:c:d:e:f").to_s
  end

  def test_parses_dash_form
    assert_equal "00:11:22:33:44:55", MAC.new("00-11-22-33-44-55").to_s
  end

  def test_parses_dotted_form
    assert_equal "00:b0:64:fd:4f:6c", MAC.new("00b0.64fd.4f6c").to_s
  end

  def test_parses_bare_hex
    assert_equal "00:11:22:33:44:55", MAC.new("001122334455").to_s
  end

  def test_parses_from_raw_bytes
    raw = ["001122334455"].pack("H*")
    assert_equal "00:11:22:33:44:55", MAC.from_bytes(raw).to_s
  end

  def test_parses_array
    assert_equal "00:11:22:33:44:55", MAC.new([0, 0x11, 0x22, 0x33, 0x44, 0x55]).to_s
  end

  def test_copy_construct
    a = MAC.new("00:11:22:33:44:55")
    assert_equal a, MAC.new(a)
  end

  def test_dotted_output
    assert_equal "0102.0304.0506", MAC.new("1:2:3:4:5:6").to_s(".")
  end

  def test_encode_is_six_bytes
    enc = MAC.new("00:11:22:33:44:55").encode
    assert_equal 6, enc.bytesize
    assert_equal "001122334455", enc.unpack1("H*")
  end

  def test_equality_and_hash
    a = MAC.new("1:2:3:4:5:6")
    b = MAC.new("01:02:03:04:05:06")
    assert_equal a, b
    assert_equal a.hash, b.hash
    assert_equal 1, [a, b].uniq.size
  end

  def test_usable_as_hash_key
    h = { MAC.new("00:11:22:33:44:55") => :x }
    assert_equal :x, h[MAC.new("00:11:22:33:44:55")]
  end

  def test_immutable
    assert MAC.new("00:11:22:33:44:55").frozen?
  end

  def test_broadcast
    assert MAC.broadcast.broadcast?
    assert MAC.broadcast.multicast?
    assert_equal "ff:ff:ff:ff:ff:ff", MAC.broadcast.to_s
  end

  def test_zero
    assert MAC.zero.zero?
    assert_equal "00:00:00:00:00:00", MAC.zero.to_s
  end

  def test_multicast_and_unicast
    assert MAC.new("01:00:5e:00:00:05").multicast?
    assert MAC.new("00:11:22:33:44:55").unicast?
  end

  def test_local_and_global_bit
    assert MAC.new("02:11:22:33:44:55").local?
    assert MAC.new("00:11:22:33:44:55").global?
  end

  def test_random_is_local_unicast
    10.times do
      m = MAC.random
      assert m.local?, "#{m} should be locally administered"
      assert m.unicast?, "#{m} should be unicast"
    end
  end

  def test_oui
    assert_equal "00:b0:64", MAC.new("00:b0:64:fd:4f:6c").oui
  end

  def test_rejects_bad_hex
    assert_raises(Datalink::AddressError) { MAC.new("zz:11:22:33:44:55") }
  end

  def test_rejects_wrong_length
    assert_raises(Datalink::AddressError) { MAC.new("00:11:22") }
    assert_raises(Datalink::AddressError) { MAC.new("00:11:22:33:44:55:66") }
  end

  def test_rejects_octet_over_255
    assert_raises(Datalink::AddressError) { MAC.new([0, 0, 0, 0, 0, 256]) }
  end

  def test_rejects_wrong_type
    assert_raises(Datalink::AddressError) { MAC.new(42) }
  end
end
