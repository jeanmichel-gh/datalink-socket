# frozen_string_literal: true

require_relative "../test_helper"
require "datalink/backends/loopback"
require "datalink/spoof"
require "datalink/attack/arp_poison"

class TestSpoofAndAttack < Minitest::Test
  include Datalink
  Loopback = Datalink::Backends::Loopback

  def setup
    @wire = Loopback::Wire.new
    @attacker = sock("attacker", 1)
    @victim = sock("victim", 2)
    @gateway = sock("gateway", 2)
    @attacker_mac = MAC.new("aa:aa:aa:aa:aa:aa")
    @victim_mac = MAC.new("11:11:11:11:11:11")
    @gateway_mac = MAC.new("22:22:22:22:22:22")
  end

  def teardown
    @threads&.each(&:kill)
    [@attacker, @victim, @gateway].each(&:close)
  end

  def sock(name, timeout)
    Datalink::Socket.new(name, backend: :loopback, wire: @wire, recv_timeout: timeout).open
  end

  def test_spoof_sends_forged_reply_to_victim
    spoof = Spoof.new(@attacker, attacker_mac: @attacker_mac)
    spoof.poison(victim_ip: "10.0.0.50", victim_mac: @victim_mac, spoofed_ip: "10.0.0.1")

    frame = @victim.recv.frame
    arp = ARP.parse(frame.payload)
    assert arp.reply?
    assert_equal "10.0.0.1", arp.sender_ip.to_s
    assert_equal @attacker_mac, arp.sender_mac, "gateway IP should now map to attacker"
    assert_equal @victim_mac, frame.dst, "poison should be unicast to the victim"
  end

  def test_restore_broadcasts_true_mapping
    spoof = Spoof.new(@attacker, attacker_mac: @attacker_mac)
    spoof.restore(ip: "10.0.0.1", mac: @gateway_mac, repeat: 1)
    frame = @victim.recv.frame
    arp = ARP.parse(frame.payload)
    assert_equal @gateway_mac, arp.sender_mac
    assert frame.dst.broadcast?
  end

  def test_full_mitm_discovers_poisons_and_forwards
    # Phase 1: discovery. Victim and gateway answer ARP for their own IPs.
    # These responders read their own sockets, so they are stopped before
    # the forwarding phase to leave the wire uncontended for the relay.
    @threads = []
    responders = [
      arp_responder(@victim, "10.0.0.50", @victim_mac),
      arp_responder(@gateway, "10.0.0.1", @gateway_mac)
    ]
    @threads.concat(responders)

    atk = Attack::ArpPoison.new(
      @attacker,
      attacker_mac: @attacker_mac, attacker_ip: "10.0.0.99",
      victim_ip: "10.0.0.50", gateway_ip: "10.0.0.1",
      forward: true, interval: 0.2
    )

    vm, gm = atk.discover(timeout: 3)
    assert_equal @victim_mac, vm
    assert_equal @gateway_mac, gm

    # Phase 2: forwarding. Stop the ARP responders so only the attacker's
    # forwarder and this test read the wire.
    responders.each(&:kill)
    responders.each(&:join)

    run_thread = Thread.new { atk.run(duration: 1.5) }
    @threads << run_thread
    sleep 0.4 # let the forwarder loop start

    # Victim sends data to the MAC it believes is the gateway (attacker).
    @victim.send(Frame.new(dst: @attacker_mac, src: @victim_mac,
                           ether_type: 0x0800, payload: "SECRET"))

    relayed = capture_data(@gateway, "SECRET", 3)
    assert relayed, "gateway should receive the relayed data frame"
    assert_equal @attacker_mac, relayed.src, "relay should rewrite source to attacker"
    assert_equal @gateway_mac, relayed.dst, "relay should rewrite dest to gateway"

    atk.stop
    run_thread.join
  end

  private

  def arp_responder(socket, ip, mac)
    target = IPAddr.new(ip)
    Thread.new do
      loop do
        frame = socket.recv.frame
        next unless frame.ether_type == EtherType::ARP

        arp = ARP.parse(frame.payload)
        socket.send(arp.build_reply(mac).to_frame) if arp.request? && arp.target_ip == target
      rescue Datalink::TimeoutError
        retry
      rescue Datalink::ParseError
        next
      end
    end
  end

  def capture_data(socket, marker, timeout)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      begin
        frame = socket.recv.frame
      rescue Datalink::TimeoutError
        next
      end
      return frame if frame.ether_type == 0x0800 && frame.payload.start_with?(marker) && frame.src == @attacker_mac
    end
    nil
  end
end
