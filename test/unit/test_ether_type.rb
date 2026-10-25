# frozen_string_literal: true

require_relative "../test_helper"

class TestEtherType < Minitest::Test
  ET = Datalink::EtherType

  def test_constants
    assert_equal 0x0800, ET::IPV4
    assert_equal 0x0806, ET::ARP
    assert_equal 0x8035, ET::RARP
    assert_equal 0x86DD, ET::IPV6
  end

  def test_names
    assert_equal "IPv4", ET.name(0x0800)
    assert_equal "ARP", ET.name(0x0806)
    assert_equal "RARP", ET.name(0x8035)
  end

  def test_unknown_name
    assert_equal "0x9999", ET.name(0x9999)
  end
end
