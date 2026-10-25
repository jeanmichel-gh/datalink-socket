# frozen_string_literal: true

require_relative "../test_helper"
require "datalink/backends/loopback"
require "datalink/arp/resolver"

class TestResolver < Minitest::Test
  include Datalink
  Loopback = Datalink::Backends::Loopback

  def setup
    @wire = Loopback::Wire.new
    @client = Datalink::Socket.new("client", backend: :loopback, wire: @wire, recv_timeout: 1).open
    @server = Datalink::Socket.new("server", backend: :loopback, wire: @wire, recv_timeout: 2).open
  end

  def teardown
    @responder&.kill
    @client.close
    @server.close
  end

  # A background host that answers ARP requests for one IP.
  def start_responder(ip:, mac:)
    target_ip = IPAddr.new(ip)
    answer_mac = MAC.new(mac)
    @responder = Thread.new do
      loop do
        frame = @server.recv.frame
        next unless frame.ether_type == EtherType::ARP

        arp = ARP.parse(frame.payload)
        next unless arp.request? && arp.target_ip == target_ip

        @server.send(arp.build_reply(answer_mac).to_frame)
      rescue Datalink::TimeoutError
        retry
      end
    end
  end

  def test_resolves_an_answering_host
    start_responder(ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:ff")
    resolver = ARP::Resolver.new(@client, sender_mac: "11:22:33:44:55:66", sender_ip: "10.0.0.2")
    mac = resolver.resolve("10.0.0.1", timeout: 2)
    assert_equal MAC.new("aa:bb:cc:dd:ee:ff"), mac
  end

  def test_returns_nil_for_silent_host
    resolver = ARP::Resolver.new(@client, sender_mac: "11:22:33:44:55:66", sender_ip: "10.0.0.2")
    mac = resolver.resolve("10.0.0.254", timeout: 0.5, retries: 1)
    assert_nil mac
  end
end
