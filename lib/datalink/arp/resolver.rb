# frozen_string_literal: true

require "ipaddr"
require "datalink/arp"
require "datalink/socket"

module Datalink
  class ARP
    # Resolve an IPv4 address to a MAC on the local segment by sending an
    # ARP request and waiting for the reply.
    #
    #   r = Datalink::ARP::Resolver.new(
    #         socket, sender_mac: my_mac, sender_ip: my_ip)
    #   mac = r.resolve("192.168.1.1", timeout: 2)   # => MAC or nil
    #
    # The socket is any open Datalink::Socket (or compatible backend).
    # The resolver does not own it and will not close it.
    class Resolver
      DEFAULT_TIMEOUT = 2.0

      def initialize(socket, sender_mac:, sender_ip:)
        @socket = socket
        @sender_mac = sender_mac.is_a?(MAC) ? sender_mac : MAC.new(sender_mac)
        @sender_ip = sender_ip.is_a?(IPAddr) ? sender_ip : IPAddr.new(sender_ip)
      end

      # Send a request for +ip+ and return the MAC that answers, or nil if
      # nothing replies within +timeout+ seconds.
      def resolve(ip, timeout: DEFAULT_TIMEOUT, retries: 2)
        target = ip.is_a?(IPAddr) ? ip : IPAddr.new(ip)
        request = ARP.request(sender_mac: @sender_mac, sender_ip: @sender_ip, target_ip: target)

        deadline = monotonic + timeout
        attempt_interval = timeout / (retries + 1)
        next_send = monotonic

        loop do
          now = monotonic
          return nil if now >= deadline

          if now >= next_send
            @socket.send(request)
            next_send = now + attempt_interval
          end

          @socket.recv_timeout = [deadline - monotonic, 0.05].max
          mac = listen_for_reply(target)
          return mac if mac
        rescue TimeoutError
          next
        end
      end

      private

      def listen_for_reply(target)
        captured = @socket.recv
        frame = captured.frame
        return nil unless frame.ether_type == EtherType::ARP

        arp = ARP.parse(frame.payload)
        return arp.sender_mac if arp.reply? && arp.sender_ip == target

        nil
      rescue ParseError
        nil
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end
end
