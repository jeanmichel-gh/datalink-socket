# CLAUDE.md

Guide for AI agents working on datalink-socket. Read this before changing anything.

## What this is

datalink-socket is a pure-Ruby layer-2 toolkit. It captures and injects
whole Ethernet frames, builds and parses ARP and RARP, and reads and
writes `.pcap` files. It also carries the IEEE 802.3 and LLC framing that
IS-IS and other link-layer protocols sit on.

It is the raw link-layer library the rest of the routing-protocol platform
builds on. isis4r speaks IS-IS over it.

## The one rule the rest follow from

**The packet and framing code is pure Ruby and needs no privileges. Only
the live backends touch a raw socket.** `MAC`, `Frame`, `LLC`, `EtherType`,
ARP and RARP are value objects and codecs: they build, encode and parse in
memory, and a test exercises them with no root and no NIC. A raw `AF_PACKET`
or `BPF` socket is reached only through `Backends::Linux` and `Backends::BPF`.

So the whole stack runs in a test over the `loopback` and `pcap_file`
backends, and that is how the suite and isis4r both use it. Keep that line:
never reach for a socket, an interface name or a capability outside a live
backend.

## Layout

datalink-socket is published as a gem, so the library lives under `lib/`,
and everything under it is namespaced under `datalink/`.

```
datalink-socket.gemspec    the gem: name datalink-socket, require_paths ["lib"]
lib/datalink.rb            entry point, requires everything
lib/datalink/version.rb    Datalink::VERSION, read by the gemspec
lib/datalink/mac.rb        MAC address value object, immutable, compares by value
lib/datalink/frame.rb      Ethernet II and IEEE 802.3 frames: encode, parse, VLAN
lib/datalink/ether_type.rb EtherType constants and names
lib/datalink/llc.rb        IEEE 802.2 LLC header (U-format): wrap and parse
lib/datalink/socket.rb     Datalink::Socket, the facade that picks a backend
lib/datalink/backends/     base, linux (AF_PACKET), bpf, loopback, pcap_file
lib/datalink/arp.rb        ARP packets, request/reply
lib/datalink/arp/resolver.rb  IP-to-MAC resolution over a live socket
lib/datalink/rarp.rb       Reverse ARP
lib/datalink/spoof.rb      ARP spoofing primitives
lib/datalink/masquerade.rb change and restore an interface MAC
lib/datalink/attack/arp_poison.rb  bidirectional MITM
lib/datalink/error.rb      the error classes
exe/                       command-line tools shipped with the gem
test/unit/                 one test file per codec, no privileges
test/functional/           the stack over loopback and pcap_file, no privileges
test/live/                 the live socket smoke test, needs root
```

A `Datalink::Socket` is a thin front door: it chooses a backend (the host
default, or one named with `backend:`) and forwards `recv`, `send` and
`each_frame` to it. The codecs know nothing about sockets.

## Platforms and privileges

| OS       | Backend   | Needs                                  |
|----------|-----------|----------------------------------------|
| Linux    | AF_PACKET | root or `CAP_NET_RAW`                  |
| macOS    | BPF       | root, or access to `/dev/bpf*`         |
| FreeBSD  | BPF       | same as macOS                          |
| any      | loopback  | nothing; in-memory, for tests          |
| any      | pcap_file | nothing; read/write `.pcap` offline    |

A raw layer-2 socket is a privileged operation. On Linux grant it without
root through the capability: `sudo setcap cap_net_raw+ep $(which ruby)`, or
run the process as root. Windows is not supported out of the box. Requires
Ruby 3.1 or newer.

## Testing

The full unit suite needs no privileges and runs anywhere:

```sh
bundle exec rake test:unit
```

`bundle exec rake test` also runs the functional suite, which drives the
whole stack over the `loopback` and `pcap_file` backends and still needs no
privileges. Both must pass before a PR.

Only the live socket smoke test needs root, and it is not part of either
suite above:

```sh
sudo ruby -Ilib test/live/smoke_linux.rb
```

So there is no part of the gated suite that privileges unlock. If a change
cannot be proved without a raw socket, it belongs behind a backend and its
logic belongs in a codec a unit test can reach.

Tests assert on the encoded bytes. A frame or packet is its wire form, so
compare `to_shex` (hex of the wire bytes) against hex worked out from the
layout, not two objects for equality.

## The contract with isis4r

isis4r depends on this gem (`datalink-socket ~> 1.0`) and its Docker image
builds with datalink-socket as a named build context
(`--build-context datalink-socket=../datalink-socket`, which copies
`lib/`). These surfaces are what isis4r speaks to; a change that renames or
reshapes one breaks it, so change them only on purpose and in step.

- `Datalink::MAC.new(str)`, value equality, usable as a Hash key.
- `Datalink::Frame.ieee_802_3(dst:, src:, payload:)`, and `Frame#sdu`,
  which returns the 802.3 payload.
- `Datalink::LLC`, including `LLC.parse(bytes) => [llc, remaining]` and
  the SAP constants (`SAP_ISIS`).
- `Datalink::Socket.new(name, backend: :loopback, wire:, recv_timeout:)`,
  then `open`, `send`, `recv` (a captured frame whose `frame` parses it),
  and `each_frame`.
- `Datalink::Backends::Loopback::Wire`, the shared medium two sockets pair
  on to simulate a segment.

## Rules for agents

- Work on a branch named `claude/<short-topic>`. Never push to master.
- One topic per PR, small diffs.
- Run the full unit suite before opening a PR. All tests must pass.
- New behavior needs a test. A bug fix needs a test that failed before it.
- Design spec first: non-trivial work gets a design in
  `docs/design/<topic>.md`, approved before any code.
- Write in plain, short sentences.
