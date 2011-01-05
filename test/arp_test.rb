require "test/unit"
require "arp"
class TestNetArp2 < Test::Unit::TestCase
  def test_arp_request
    req = Arp.new_request :hw_src=> '1:2:3:4:5:6', :proto_src=> '10.0.0.1', :proto_tgt=>'10.0.0.2'
    assert_equal(1, req.opcode)
    assert_equal('01:02:03:04:05:06', req.hw_src.to_s)
    assert_equal('00:00:00:00:00:00', req.hw_tgt.to_s)
    assert_equal('10.0.0.1', req.proto_src.to_s)
    assert_equal('10.0.0.2', req.proto_tgt.to_s)
    assert_equal('ffffffffffff010203040506080600010800060400010102030405060a0000010000000000000a000002', req.to_shex)
  end
  def test_arp_reply
    req = Arp.new_request :hw_src=> '1:2:3:4:5:6', :proto_src=> '10.0.0.1', :proto_tgt=>'10.0.0.2'
    reply  = req.reply '00:50:56:c0:00:01'
    #TODO finish test
  end  
end
