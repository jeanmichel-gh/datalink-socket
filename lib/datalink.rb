# frozen_string_literal: true

# Datalink: capture and inject raw Ethernet (layer 2) frames in Ruby,
# with ARP and RARP protocol support and tooling for spoofing,
# MAC masquerade, and ARP cache-poisoning attacks.
#
# Entry points:
#   Datalink::Socket.open(ifname) { |sock| ... }   # live capture/inject
#   Datalink::MAC.new("00:11:22:33:44:55")         # address value object
#   Datalink::Frame.new(...)                        # Ethernet frame
#   Datalink::ARP.request(...)  / Datalink::RARP     # protocols
#   Datalink::Spoof, Datalink::Masquerade            # offensive helpers
#   Datalink::Attack::ArpPoison                       # MITM
#
# The protocol and frame classes are pure Ruby and need no privileges.
# The live backends need root (or CAP_NET_RAW on Linux). For tests and
# offline work, use the :loopback and :pcap_file backends.

require "datalink/version"
require "datalink/error"
require "datalink/mac"
require "datalink/ether_type"
require "datalink/frame"
require "datalink/socket"
require "datalink/arp"
require "datalink/rarp"

module Datalink
end
