# frozen_string_literal: true

# Live smoke test for the real AF_PACKET backend. Needs root or
# CAP_NET_RAW. Not part of the default suite (that one needs no
# privileges); run it where raw sockets are allowed:
#
#   sudo ruby -Ilib test/live/smoke_linux.rb
#
# It opens two raw sockets on the loopback interface, sends a crafted
# Ethernet frame on one, and confirms the other captures it off the
# kernel. This exercises the code path the mock backends cannot: bind to
# an interface, send, and recvfrom.

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
require "datalink"

abort "this smoke test is Linux-only" unless RUBY_PLATFORM.include?("linux")

IFACE = ENV.fetch("DL_IFACE", "lo")
MARKER = "DL-SMOKE-#{Process.pid}"

sender = Datalink::Socket.open(IFACE)
sniffer = Datalink::Socket.open(IFACE, recv_timeout: 3)

frame = Datalink::Frame.new(
  dst: Datalink::MAC.broadcast,
  src: Datalink::MAC.new("02:00:00:00:00:01"),
  ether_type: 0x88b5, # IEEE local experimental EtherType
  payload: MARKER
)

captured = nil
reader = Thread.new do
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
  while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    f = sniffer.recv.frame
    if f.ether_type == 0x88b5 && f.payload.start_with?(MARKER)
      captured = f
      break
    end
  end
rescue Datalink::TimeoutError
  nil
end

sleep 0.2
sender.send(frame)
reader.join

sender.close
sniffer.close

unless captured
  warn "FAIL: did not capture the test frame on #{IFACE}"
  exit 1
end
puts "OK: live AF_PACKET round-trip on #{IFACE} (#{captured})"

# Outgoing frames. A socket sees what another socket on the interface
# sends as :outgoing, and ignore_outgoing: true drops those. Measured on
# Linux 7.0: on lo the outgoing copy comes with a looped-back one, which
# both sockets see; on a veth only the outgoing copy is seen here.
MARKER2 = "DL-OUT-#{Process.pid}"

def types_seen(sock, marker)
  types = []
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
  while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    c = sock.recv
    types << c.packet_type if c.bytes.include?(marker)
  end
rescue Datalink::TimeoutError
  types
else
  types
end

sender = Datalink::Socket.open(IFACE)
plain = Datalink::Socket.open(IFACE, recv_timeout: 2)
quiet = Datalink::Socket.open(IFACE, recv_timeout: 2, ignore_outgoing: true)
seen = {}
readers = { plain: plain, quiet: quiet }.map do |name, sock|
  Thread.new { seen[name] = types_seen(sock, MARKER2) }
end
sleep 0.2
sender.send(Datalink::Frame.new(dst: Datalink::MAC.broadcast,
                                src: Datalink::MAC.new("02:00:00:00:00:02"),
                                ether_type: 0x88b5, payload: MARKER2))
readers.each(&:join)
[sender, plain, quiet].each(&:close)

unless seen[:plain].include?(:outgoing)
  warn "FAIL: a plain socket did not see the frame as outgoing on #{IFACE}: #{seen[:plain].inspect}"
  exit 1
end
if seen[:quiet].include?(:outgoing)
  warn "FAIL: ignore_outgoing still saw an outgoing frame on #{IFACE}: #{seen[:quiet].inspect}"
  exit 1
end
puts "OK: outgoing on #{IFACE}: plain saw #{seen[:plain].inspect}, ignore_outgoing saw #{seen[:quiet].inspect}"
exit 0
