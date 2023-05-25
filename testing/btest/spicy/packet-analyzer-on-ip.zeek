# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto spicy/raw-layer.pcap.spicy spicy/raw-layer.pcap.evt
# @TEST-EXEC: zeek -r ${TRACES}/dns/proto255.pcap test.hlto %INPUT >output
# @TEST-EXEC: btest-diff output

module PacketAnalyzer::SPICY_RAWLAYER;

event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 255, "spicy_RawLayer") ) # modified trace to have IP proto 255
		print "cannot register raw analyzer on top of IP";
	}

event raw::data(p: raw_pkt_hdr, data: string)
	{
    print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
    print fmt("IPs : src=%s dst=%s", p$ip$src, p$ip$dst);
	print fmt("raw bytes: %d", |data|);
	}

# @TEST-START-FILE spicy/raw-layer.pcap.spicy
module RawLayer;

import zeek;

public type Packet = unit {
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE spicy/raw-layer.pcap.evt
packet analyzer spicy::RawLayer:
    parse with RawLayer::Packet;

on RawLayer::Packet::data -> event raw::data($packet, self.data);
# @TEST-END-FILE
