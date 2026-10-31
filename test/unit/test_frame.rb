# frozen_string_literal: true

require_relative "../test_helper"

class TestFrame < Minitest::Test
  include Datalink
  Frame = Datalink::Frame

  def test_build_from_strings
    f = Frame.new(dst: "00:04:00:05:00:06", src: "00:01:00:02:00:03", ether_type: 0x0800)
    assert_equal "00:01:00:02:00:03", f.src.to_s
    assert_equal "00:04:00:05:00:06", f.dst.to_s
    assert_equal 0x0800, f.ether_type
  end

  def test_build_from_mac_objects
    f = Frame.new(dst: MAC.broadcast, src: MAC.new("11:22:33:44:55:66"), ether_type: 0x0806)
    assert f.dst.broadcast?
  end

  def test_encode_header_bytes
    f = Frame.new(dst: "00:04:00:05:00:06", src: "00:01:00:02:00:03", ether_type: 0x0800)
    assert_equal "0004000500060001000200030800", f.to_shex
  end

  def test_parse_roundtrip
    f = Frame.new(dst: "ff:ff:ff:ff:ff:ff", src: "11:22:33:44:55:66",
                  ether_type: 0x0806, payload: "hello")
    g = Frame.parse(f.encode)
    assert_equal f.dst, g.dst
    assert_equal f.src, g.src
    assert_equal f.ether_type, g.ether_type
    assert_equal "hello", g.payload
  end

  def test_parse_known_frame
    hex = "01005e00000500b064fd4f6c0800" \
          "45c0004084fe000001599131c0a801c8e0000005"
    f = Frame.parse([hex].pack("H*"))
    assert_equal 0x0800, f.ether_type
    assert_equal "00:b0:64:fd:4f:6c", f.src.to_s
    assert_equal "01:00:5e:00:00:05", f.dst.to_s
  end

  def test_payload_from_encodable
    arp = ARP.new_request(sender_mac: "1:2:3:4:5:6", sender_ip: "10.0.0.1", target_ip: "10.0.0.2")
    f = Frame.new(dst: MAC.broadcast, src: "1:2:3:4:5:6", ether_type: EtherType::ARP, payload: arp)
    assert_equal arp.encode, f.payload
  end

  def test_vlan_roundtrip
    f = Frame.new(dst: "ff:ff:ff:ff:ff:ff", src: "11:22:33:44:55:66",
                  ether_type: 0x0800, vlan_id: 100, vlan_priority: 3, payload: "x")
    g = Frame.parse(f.encode)
    assert g.vlan?
    assert_equal 100, g.vlan_id
    assert_equal 3, g.vlan_priority
    assert_equal 0x0800, g.ether_type
  end

  def test_padding
    f = Frame.new(dst: MAC.zero, src: MAC.zero, ether_type: 0x0800, payload: "ab")
    assert_equal 14 + 2, f.encode.bytesize
    assert_equal 14 + Frame::MIN_PAYLOAD, f.encode(pad: true).bytesize
  end

  def test_ethernet_v2_vs_802_3
    assert Frame.new(ether_type: 0x0800).ethernet_v2?
    assert Frame.new(ether_type: 0x0010).ieee_802_3?
  end

  def test_rejects_short_frame
    assert_raises(Datalink::ParseError) { Frame.parse("abc") }
  end

  def test_rejects_truncated_vlan
    bytes = ["ffffffffffff1122334455668100"].pack("H*")
    assert_raises(Datalink::ParseError) { Frame.parse(bytes) }
  end

  def test_ieee_802_3_builder_sets_length
    f = Frame.ieee_802_3(dst: MAC.broadcast, src: "11:22:33:44:55:66", payload: "hello")
    assert f.ieee_802_3?
    assert_equal 5, f.ether_type
  end

  def test_sdu_trims_nic_padding
    # An 802.3 frame declaring length 5, but received padded to 46 bytes.
    f = Frame.ieee_802_3(dst: MAC.broadcast, src: "11:22:33:44:55:66", payload: "hello")
    padded = Frame.parse(f.encode(pad: true))
    assert_equal 46, padded.payload.bytesize
    assert_equal "hello", padded.sdu
  end

  def test_sdu_is_full_payload_for_ethernet_v2
    f = Frame.new(dst: MAC.zero, src: MAC.zero, ether_type: 0x0800, payload: "data")
    assert_equal "data", f.sdu
  end

  def test_sdu_roundtrip_unpadded
    f = Frame.ieee_802_3(dst: MAC.broadcast, src: "11:22:33:44:55:66", payload: "abc")
    assert_equal "abc", Frame.parse(f.encode).sdu
  end
end
