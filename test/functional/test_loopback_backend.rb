# frozen_string_literal: true

require_relative "../test_helper"
require "datalink/backends/loopback"

class TestLoopbackBackend < Minitest::Test
  include Datalink
  Loopback = Datalink::Backends::Loopback

  def setup
    @wire = Loopback::Wire.new
    @a = Datalink::Socket.new("a", backend: :loopback, wire: @wire, recv_timeout: 1).open
    @b = Datalink::Socket.new("b", backend: :loopback, wire: @wire, recv_timeout: 1).open
  end

  def teardown
    @a.close
    @b.close
  end

  def test_send_is_received_by_other_endpoint
    frame = Frame.new(dst: MAC.broadcast, src: "11:22:33:44:55:66",
                      ether_type: 0x0806, payload: "data")
    @a.send(frame)
    got = @b.recv.frame
    assert_equal "data", got.payload
    assert_equal "11:22:33:44:55:66", got.src.to_s
  end

  def test_sender_does_not_receive_own_frame
    @a.send(Frame.new(dst: MAC.broadcast, src: "11:22:33:44:55:66", ether_type: 0x0800))
    assert_raises(Datalink::TimeoutError) { @a.recv }
  end

  def test_timeout_when_nothing_sent
    assert_raises(Datalink::TimeoutError) { @b.recv }
  end

  def test_each_frame_enumerates_until_quiet
    3.times { |i| @a.send(Frame.new(dst: MAC.broadcast, src: "11:22:33:44:55:66", ether_type: 0x0800, payload: i.to_s)) }
    payloads = []
    @b.each_frame { |f| payloads << f.payload }
    assert_equal %w[0 1 2], payloads
  end

  def test_arp_request_reply_over_wire
    client = @a
    server = @b
    server_mac = MAC.new("aa:bb:cc:dd:ee:ff")

    client.send(ARP.request(sender_mac: "11:22:33:44:55:66",
                            sender_ip: "10.0.0.2", target_ip: "10.0.0.1"))

    req = ARP.parse(server.recv.frame.payload)
    assert req.request?
    assert_equal "10.0.0.1", req.target_ip.to_s

    server.send(req.build_reply(server_mac).to_frame)
    reply = ARP.parse(client.recv.frame.payload)
    assert reply.reply?
    assert_equal server_mac, reply.sender_mac
    assert_equal "10.0.0.1", reply.sender_ip.to_s
  end
end
