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

if captured
  puts "OK: live AF_PACKET round-trip on #{IFACE} (#{captured})"
  exit 0
else
  warn "FAIL: did not capture the test frame on #{IFACE}"
  exit 1
end
