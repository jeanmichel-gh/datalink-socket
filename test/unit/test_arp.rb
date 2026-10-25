# frozen_string_literal: true

require_relative "../test_helper"

class TestARP < Minitest::Test
  include Datalink
  ARP = Datalink::ARP

  # The wire vector the original datalink-socket library asserted, so the
  # new code stays byte-compatible with captures made against the old one.
  OLD_REQUEST_FRAME =
    "ffffffffffff010203040506080600010800060400010102030405060a0000010000000000000a000002"

  def test_request_matches_legacy_wire_format
    arp = ARP.new(opcode: ARP::REQUEST, sender_mac: "1:2:3:4:5:6",
                  sender_ip: "10.0.0.1", target_ip: "10.0.0.2")
    assert_equal OLD_REQUEST_FRAME, arp.to_frame.to_shex
  end

  def test_request_fields
    arp = ARP.new_request(sender_mac: "1:2:3:4:5:6", sender_ip: "10.0.0.1", target_ip: "10.0.0.2")
    assert_equal ARP::REQUEST, arp.opcode
    assert arp.request?
    assert_equal "01:02:03:04:05:06", arp.sender_mac.to_s
    assert_equal "00:00:00:00:00:00", arp.target_mac.to_s
    assert_equal "10.0.0.1", arp.sender_ip.to_s
    assert_equal "10.0.0.2", arp.target_ip.to_s
  end

  def test_payload_roundtrip
    arp = ARP.new_request(sender_mac: "aa:bb:cc:dd:ee:ff", sender_ip: "192.168.1.1",
                          target_ip: "192.168.1.2")
    back = ARP.parse(arp.encode)
    assert_equal arp.opcode, back.opcode
    assert_equal arp.sender_mac, back.sender_mac
    assert_equal arp.sender_ip, back.sender_ip
    assert_equal arp.target_ip, back.target_ip
  end

  def test_parse_from_full_frame
    arp = ARP.new_request(sender_mac: "aa:bb:cc:dd:ee:ff", sender_ip: "192.168.1.1",
                          target_ip: "192.168.1.2")
    back = ARP.parse(arp.to_frame.encode)
    assert back.request?
    assert_equal "192.168.1.2", back.target_ip.to_s
  end

  def test_request_is_broadcast_frame
    arp = ARP.new_request(sender_mac: "1:2:3:4:5:6", sender_ip: "10.0.0.1", target_ip: "10.0.0.2")
    assert arp.to_frame.dst.broadcast?
  end

  def test_build_reply
    req = ARP.new_request(sender_mac: "1:2:3:4:5:6", sender_ip: "10.0.0.1", target_ip: "10.0.0.2")
    reply = req.build_reply("00:50:56:c0:00:01")
    assert reply.reply?
    assert_equal "00:50:56:c0:00:01", reply.sender_mac.to_s
    assert_equal "10.0.0.2", reply.sender_ip.to_s   # the IP we answer for
    assert_equal "01:02:03:04:05:06", reply.target_mac.to_s
    assert_equal "10.0.0.1", reply.target_ip.to_s
  end

  def test_reply_frame_is_unicast_to_requester
    req = ARP.new_request(sender_mac: "1:2:3:4:5:6", sender_ip: "10.0.0.1", target_ip: "10.0.0.2")
    reply = req.build_reply("00:50:56:c0:00:01")
    assert_equal "01:02:03:04:05:06", reply.to_frame.dst.to_s
  end

  def test_reply_shortcut
    frame = ARP.reply(sender_mac: "00:50:56:c0:00:01", sender_ip: "10.0.0.2",
                      target_mac: "1:2:3:4:5:6", target_ip: "10.0.0.1")
    parsed = ARP.parse(frame.payload)
    assert parsed.reply?
  end

  def test_rejects_non_ethernet
    # htype 2, not Ethernet
    bad = [2, 0x0800, 6, 4, 1].pack("nnCCn") + ("\x00" * 20)
    assert_raises(Datalink::ParseError) { ARP.parse(bad) }
  end

  def test_rejects_short
    assert_raises(Datalink::ParseError) { ARP.parse("abc") }
  end

  def test_to_s
    req = ARP.new_request(sender_mac: "1:2:3:4:5:6", sender_ip: "10.0.0.1", target_ip: "10.0.0.2")
    assert_match(/who-has 10\.0\.0\.2 tell 10\.0\.0\.1/, req.to_s)
  end
end
