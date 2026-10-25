# Changelog

## 1.0.0 (2026-10-25)

A full rewrite of the 2011 library into a modern, tested layer-2 toolkit.

### Added
- `Datalink::MAC`: immutable MAC value object with parsing, equality,
  hashing, broadcast/multicast/local tests, and `MAC.random`.
- `Datalink::Frame`: Ethernet II frame with encode/parse, 802.1Q VLAN
  tag support, and padding.
- `Datalink::Socket`: one facade over pluggable backends.
- Backends: `linux` (AF_PACKET), `bpf` (macOS/BSD), plus `loopback` and
  `pcap_file` for privilege-free testing and offline work.
- `Datalink::ARP` and `Datalink::ARP::Resolver`.
- `Datalink::RARP`.
- `Datalink::Spoof`, `Datalink::Masquerade`, and
  `Datalink::Attack::ArpPoison` (bidirectional MITM with forwarding and
  cache restore).
- Example CLIs: `arp-scan`, `arp-spoof`.
- Minitest unit and functional suites (69 tests), CI for Ruby 3.1-3.4.

### Changed from the 2011 version
- No more core-class monkey-patching (`ruby-ext.rb` is gone).
- Platform is detected from `RUBY_PLATFORM`, not by shelling out to
  `uname` at require time.
- Backends share one interface instead of two divergent `recv` shapes.
- The Linux backend composes a `::Socket` rather than subclassing it,
  avoiding a constant-name collision with `Datalink::Socket`.
- ARP no longer builds its own Ethernet header; the Frame layer does.

### Compatibility
- The ARP request wire format is byte-identical to the 2011 library, so
  captures and tests against the old version still match.
