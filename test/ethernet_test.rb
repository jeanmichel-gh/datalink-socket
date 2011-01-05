require "test/unit"

require "ethernet"

class TestEthernetIeAddress < Test::Unit::TestCase
  def test_create_address
    assert Ethernet::Address.new
    assert Ethernet::Address.new '00:01:02:03:04:05'
    assert_equal '01:02:03:04:05:06', Ethernet::Address.new('1:2:3:4:5:6').to_s
    assert_equal '0a:0b:0c:0d:0e:0f', Ethernet::Address.new('a:b:c:d:e:f').to_s
    assert_equal '00:b0:64:fd:4f:6c', Ethernet::Address.new('00b0.64fd.4f6c').to_s
  end
  def test_to_s
    assert_equal '0102.0304.0506', Ethernet::Address.new('1:2:3:4:5:6').to_s('.')
    assert_equal '0a0b.0c0d.0e0f', Ethernet::Address.new('a:b:c:d:e:f').to_s('.')
    assert_equal '00b0.64fd.4f6c', Ethernet::Address.new('00b0.64fd.4f6c').to_s('.')
  end
  def test_encode
    assert_equal '010203040506', Ethernet::Address.new('1:2:3:4:5:6').to_shex
    assert_equal '0a0b0c0d0e0f', Ethernet::Address.new('a:b:c:d:e:f').to_shex
  end
  def test_parse
    assert_equal Ethernet::Address, Ethernet::Address.new(['010203040506'].pack('H*')).class
    assert_equal '010203040506', Ethernet::Address.new(['010203040506'].pack('H*')).to_shex
  end
  # def test_to_s_oui
  #   assert_equal 'Apple_d8:93:a4',   Ethernet::Address.new('00:1f:f3:d8:93:a4').to_s_oui
  #   assert_equal 'Dell_01:3e:3d',    Ethernet::Address.new('00:21:9b:01:3e:3d').to_s_oui
  #   assert_equal 'Hewlett_64:66:73', Ethernet::Address.new('00:50:8b:64:66:73').to_s_oui
  #   assert_equal 'Intel_40:b8:8f',   Ethernet::Address.new('0:2:b3:40:b8:8f').to_s_oui
  #   assert_equal 'Cisco_fd:4f:6c',   Ethernet::Address.new('00b0.64fd.4f6c').to_s_oui
  # end
end

class TestEthernetType < Test::Unit::TestCase
  def test_case_name
    assert_equal 2054, Ethernet::Type::ETH_ARP
    assert_equal 2048, Ethernet::Type::ETH_IPv4
    assert_equal 34525, Ethernet::Type::ETH_IPv6
    assert_equal 32821, Ethernet::Type::ETH_RARP
    assert_equal 'ARP',Ethernet::Type.to_s(2054)
    assert_equal 'RARP',Ethernet::Type.to_s(32821)
    assert_equal 'IPv4',Ethernet::Type.to_s(2048)
    assert_equal 'AppleTalk Ethertalk',Ethernet::Type.to_s(0x809B)
  end
end

class TestEthernetFrame < Test::Unit::TestCase
  include Ethernet
  def test_create_a_frame
    frame = Ethernet::Frame.new :src=> '0001.0002.0003', :dst=>'0004.0005.0006', :ether_type=>0x800
    assert_equal '00:01:00:02:00:03', frame.src.to_s
    assert_equal '00:04:00:05:00:06', frame.dst.to_s
    assert_equal 2048, frame.ether_type
    frame = Ethernet::Frame.new(['0004000500060001000200030800'].pack('H*'))
    assert_equal '00:01:00:02:00:03', frame.src.to_s
    assert_equal '00:04:00:05:00:06', frame.dst.to_s
    assert_equal 2048, frame.ether_type
  end
  def test_create_ntop_ip
    s = '01005e00000500b064fd4f6c0800' +
    '45c0004084fe000001599131c0a801c8e0000005' + 
    '0201002c0200000000000000fa1f00000000000000000000ffffff00000a0280000000280000000000000000'
    sbin  = [s].pack('H*')
    frame = Frame.new(sbin)
    # assert_equal 'Cisco_fd:4f:6c', frame.src.to_s_oui
    # assert_equal '01:00:5e:00:00:05', frame.dst.to_s_oui
    assert_equal 2048, frame.ether_type
    assert_equal '45c0004084fe000001599131c0a801c8e000000502', frame.payload[0..20].unpack('H*')[0]
  end
end