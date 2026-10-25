# frozen_string_literal: true

require_relative "../test_helper"
require "datalink/backends/pcap_file"
require "tmpdir"

class TestPcapFileBackend < Minitest::Test
  include Datalink

  def test_write_then_read_roundtrip
    Dir.mktmpdir do |dir|
      path = File.join(dir, "out.pcap")

      Datalink::Socket.open(path, backend: :pcap_file, mode: :write) do |w|
        w.send(Frame.new(dst: MAC.broadcast, src: "11:22:33:44:55:66",
                         ether_type: 0x0806, payload: "one"))
        w.send(Frame.new(dst: "00:00:00:00:00:01", src: "00:00:00:00:00:02",
                         ether_type: 0x0800, payload: "two"))
      end

      frames = []
      Datalink::Socket.open(path, backend: :pcap_file, mode: :read) do |r|
        r.each_frame { |f| frames << f }
      end

      assert_equal 2, frames.size
      assert_equal "one", frames[0].payload
      assert_equal 0x0806, frames[0].ether_type
      assert_equal "two", frames[1].payload
    end
  end

  def test_pcap_magic_is_written
    Dir.mktmpdir do |dir|
      path = File.join(dir, "out.pcap")
      Datalink::Socket.open(path, backend: :pcap_file, mode: :write) do |w|
        w.send(Frame.new(dst: MAC.zero, src: MAC.zero, ether_type: 0x0800))
      end
      magic = File.binread(path, 4).unpack1("N")
      assert_equal 0xa1b2c3d4, magic
    end
  end

  def test_rejects_non_pcap
    Dir.mktmpdir do |dir|
      path = File.join(dir, "junk.bin")
      File.binwrite(path, "not a pcap file at all, really")
      assert_raises(Datalink::ParseError) do
        Datalink::Socket.open(path, backend: :pcap_file, mode: :read, &:recv)
      end
    end
  end

  def test_eof_raises_timeout
    Dir.mktmpdir do |dir|
      path = File.join(dir, "empty.pcap")
      Datalink::Socket.open(path, backend: :pcap_file, mode: :write) { |_w| }
      Datalink::Socket.open(path, backend: :pcap_file, mode: :read) do |r|
        assert_raises(Datalink::TimeoutError) { r.recv }
      end
    end
  end
end
