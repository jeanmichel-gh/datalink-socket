# frozen_string_literal: true

module Datalink
  # EtherType values (the 16-bit Type field of an Ethernet II frame) and
  # a name lookup. Values below 0x0600 are IEEE 802.3 length fields, not
  # EtherTypes; Frame#ethernet_v2? distinguishes the two.
  module EtherType
    IPV4       = 0x0800
    ARP        = 0x0806
    RARP       = 0x8035
    APPLETALK  = 0x809B
    AARP       = 0x80F3
    VLAN       = 0x8100  # IEEE 802.1Q
    IPV6       = 0x86DD
    MPLS       = 0x8847
    LLDP       = 0x88CC
    QINQ       = 0x88A8  # IEEE 802.1ad

    NAMES = {
      IPV4      => "IPv4",
      ARP       => "ARP",
      RARP      => "RARP",
      APPLETALK => "AppleTalk",
      AARP      => "AppleTalk ARP",
      VLAN      => "802.1Q VLAN",
      IPV6      => "IPv6",
      MPLS      => "MPLS",
      LLDP      => "LLDP",
      QINQ      => "802.1ad QinQ"
    }.freeze

    # Human-readable name, or "0xNNNN" for an unknown type.
    def self.name(type)
      NAMES[type] || format("0x%04x", type)
    end
  end
end
