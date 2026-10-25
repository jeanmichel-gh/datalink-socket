# datalink-socket

Capture and inject raw Ethernet (layer 2) frames in Ruby, with ARP and
RARP, and tooling for ARP spoofing, MAC masquerade, and a
man-in-the-middle ARP cache-poisoning attack.

This is a ground-up rewrite of the original 2011 library. The packet and
protocol code is pure Ruby and needs no privileges. The live backends
(AF_PACKET on Linux, BPF on macOS/BSD) need root or `CAP_NET_RAW`. For
tests and offline work there are `loopback` and `pcap_file` backends that
run anywhere.

## Install

```sh
gem install datalink-socket
```

Or in a Gemfile:

```ruby
gem "datalink-socket"
```

Requires Ruby 3.1 or newer.

## Layout

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

## Quick start

### Build and read frames

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
```

### Capture and inject live (needs root)

```ruby
Datalink::Socket.open("eth0") do |sock|
  sock.recv_timeout = 2
  sock.each_frame { |f| puts f }   # prints until quiet
  sock.send(frame)
end
```

### ARP

```ruby
# Build a request (returns a ready-to-send broadcast frame)
req = Datalink::ARP.request(
  sender_mac: "00:11:22:33:44:55",
  sender_ip:  "192.168.1.10",
  target_ip:  "192.168.1.1"
)

# Resolve an IP to a MAC over a live socket
Datalink::Socket.open("eth0") do |sock|
  r = Datalink::ARP::Resolver.new(sock, sender_mac: my_mac, sender_ip: my_ip)
  mac = r.resolve("192.168.1.1", timeout: 2)   # => MAC or nil
end
```

### RARP

```ruby
# A diskless host asking for its own IP (knows only its MAC)
Datalink::RARP.request(sender_mac: my_mac, target_mac: my_mac)

# A server answering with the assigned IP
Datalink::RARP.reply(
  sender_mac: server_mac, sender_ip: server_ip,
  target_mac: client_mac, target_ip: "192.168.1.50"
)
```

### Read and write pcap files (no privileges)

```ruby
Datalink::Socket.open("out.pcap", backend: :pcap_file, mode: :write) do |w|
  w.send(frame)
end
# out.pcap opens in Wireshark.
```

## Offensive tooling

These intercept or forge traffic. **Only use them on networks you own or
are explicitly authorized to test. Forging ARP or intercepting traffic on
other networks is illegal in most places.**

### Spoof one host

```ruby
Datalink::Socket.open("eth0") do |sock|
  s = Datalink::Spoof.new(sock, attacker_mac: my_mac)
  s.poison(victim_ip: "192.168.1.50", victim_mac: victim_mac,
           spoofed_ip: "192.168.1.1")   # victim now thinks gw is at my MAC
  # ... later ...
  s.restore(ip: "192.168.1.1", mac: real_gateway_mac)  # heal the cache
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
  atk.run(duration: 60)   # poisons both sides, forwards, restores on exit
end
```

### Command-line examples

```sh
# Discover hosts on a subnet
sudo ruby -Ilib exe/arp-scan -i eth0 -s 192.168.1.10 -m <mac> 192.168.1.0/24

# Run a MITM for 60s (prompts for confirmation)
sudo ruby -Ilib exe/arp-spoof -i eth0 -s 192.168.1.99 -m <mac> \
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

Windows is not supported out of the box; raw L2 there needs Npcap and a
separate backend.

## Tests

```sh
bundle install
bundle exec rake test            # unit + functional, no privileges
bundle exec rake test:unit
bundle exec rake test:functional

# Live backend (needs root):
sudo ruby -Ilib test/live/smoke_linux.rb
```

## License

Same terms as Ruby. See `LICENSE`.
