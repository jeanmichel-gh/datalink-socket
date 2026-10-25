# frozen_string_literal: true

require_relative "../test_helper"

class TestRARP < Minitest::Test
  include Datalink
  RARP = Datalink::RARP

  def test_request_opcode_and_ethertype
    req = RARP.new_request(sender_mac: "11:22:33:44:55:66", target_mac: "11:22:33:44:55:66")
    assert_equal RARP::REQUEST, req.opcode
    assert req.request?
    assert_equal EtherType::RARP, req.to_frame.ether_type
  end

  def test_payload_roundtrip
    req = RARP.new_request(sender_mac: "11:22:33:44:55:66", target_mac: "aa:bb:cc:dd:ee:ff")
    back = RARP.parse(req.encode)
    assert_equal req.opcode, back.opcode
    assert_equal req.sender_mac, back.sender_mac
    assert_equal req.target_mac, back.target_mac
  end

  def test_parse_from_frame
    req = RARP.new_request(sender_mac: "11:22:33:44:55:66", target_mac: "11:22:33:44:55:66")
    back = RARP.parse(req.to_frame.encode)
    assert back.request?
  end

  def test_build_reply_assigns_ip
    req = RARP.new_request(sender_mac: "11:22:33:44:55:66", target_mac: "11:22:33:44:55:66")
    reply = req.build_reply(server_mac: "aa:bb:cc:dd:ee:ff", server_ip: "192.168.1.1",
                            assigned_ip: "192.168.1.50")
    assert reply.reply?
    assert_equal RARP::REPLY, reply.opcode
    assert_equal "192.168.1.50", reply.target_ip.to_s
    assert_equal "11:22:33:44:55:66", reply.target_mac.to_s
  end

  def test_reply_is_unicast
    reply = RARP.new_reply(sender_mac: "aa:bb:cc:dd:ee:ff", sender_ip: "192.168.1.1",
                           target_mac: "11:22:33:44:55:66", target_ip: "192.168.1.50")
    assert_equal "11:22:33:44:55:66", reply.to_frame.dst.to_s
  end

  def test_opcodes_differ_from_arp
    refute_equal Datalink::ARP::REQUEST, RARP::REQUEST
    refute_equal Datalink::ARP::REPLY, RARP::REPLY
  end

  def test_rejects_short
    assert_raises(Datalink::ParseError) { RARP.parse("abc") }
  end
end
