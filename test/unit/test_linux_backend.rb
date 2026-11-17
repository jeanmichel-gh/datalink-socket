# frozen_string_literal: true

require_relative "../test_helper"
require "datalink/backends/linux"

# The Linux backend's packet types, with no raw socket. A sockaddr_ll is
# built from its layout (linux/if_packet.h): family u16, protocol be16,
# ifindex s32, hatype u16, pkttype u8, halen u8, addr[8]. The live side
# is test/live/smoke_linux.rb.
class TestLinuxBackend < Minitest::Test
  Linux = Datalink::Backends::Linux
  CapturedFrame = Datalink::Backends::CapturedFrame

  def sockaddr_ll(pkttype)
    [17, 0x88b5, 1, 1, pkttype, 6].pack("S n l S C C") + ("\x00".b * 8)
  end

  # Measured on Linux 7.0 with Ruby 3.3: recvfrom on lo answered this
  # sockaddr for a broadcast frame, pkttype 2 at byte 10.
  def test_packet_type_of_a_measured_sockaddr
    sa = ["110088b501000000040302060200000000010000"].pack("H*")
    assert_equal :multicast, Linux.packet_type(sa)
  end

  def test_packet_type_of_each_kernel_value
    expect = { 0 => :host, 1 => :broadcast, 2 => :multicast, 3 => :otherhost, 4 => :outgoing }
    expect.each { |n, sym| assert_equal sym, Linux.packet_type(sockaddr_ll(n)), "pkttype #{n}" }
  end

  def test_an_unknown_packet_type_is_its_number
    assert_equal 7, Linux.packet_type(sockaddr_ll(7))
  end

  def test_a_short_sockaddr_has_no_packet_type
    assert_nil Linux.packet_type("\x11\x00".b)
    assert_nil Linux.packet_type(nil)
  end

  def test_captured_frame_says_outgoing
    assert CapturedFrame.new("x".b, Time.now, :outgoing).outgoing?
    refute CapturedFrame.new("x".b, Time.now, :host).outgoing?
  end

  # Backends that cannot tell keep the two-argument form, and say nil.
  def test_captured_frame_without_a_packet_type
    f = CapturedFrame.new("x".b, Time.now)
    assert_nil f.packet_type
    refute f.outgoing?
  end

  def test_ignore_outgoing_is_an_option
    refute Linux.new("eth0").ignore_outgoing?
    assert Linux.new("eth0", ignore_outgoing: true).ignore_outgoing?
  end

  # A stand-in for the raw socket: recvfrom answers queued frames, each
  # with an Addrinfo-like address that gives its sockaddr_ll.
  class FakeRaw
    Addr = Struct.new(:to_sockaddr)

    def initialize(frames)
      @frames = frames
    end

    def recvfrom(_len)
      @frames.shift
    end
  end

  # A kernel older than 4.20 has no PACKET_IGNORE_OUTGOING, so the
  # backend drops outgoing frames itself. recv must skip them and answer
  # the next frame that came in.
  def test_recv_skips_outgoing_when_the_kernel_cannot
    b = Linux.new("eth0", ignore_outgoing: true)
    raw = FakeRaw.new([["out".b, FakeRaw::Addr.new(sockaddr_ll(4))],
                       ["in".b, FakeRaw::Addr.new(sockaddr_ll(0))]])
    b.__send__(:attach_for_test, raw, filter_outgoing: true)
    f = b.recv
    assert_equal "in", f.bytes
    assert_equal :host, f.packet_type
  end

  def test_recv_keeps_outgoing_by_default
    b = Linux.new("eth0")
    raw = FakeRaw.new([["out".b, FakeRaw::Addr.new(sockaddr_ll(4))]])
    b.__send__(:attach_for_test, raw, filter_outgoing: false)
    f = b.recv
    assert_equal "out", f.bytes
    assert f.outgoing?
  end
end
