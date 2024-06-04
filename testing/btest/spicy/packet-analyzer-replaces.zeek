# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o my-ethernet.hlto my-ethernet.spicy my-ethernet.evt
# @TEST-EXEC: zeek -r ${TRACES}/dns53.pcap my-ethernet.hlto %INPUT >output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Check that we can replace Zeek's Ethernet analyzer.

module MyEthernet;

const DLT_EN10MB : count = 1;

event zeek_init()
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_SPICY_MYETHERNET, 0x0800, PacketAnalyzer::ANALYZER_IP);
	}

event MyEthernet::data(p: raw_pkt_hdr, data: string)
	{
	print "My Ethernet:", data;
	}

event udp_request(u: connection)
	{
	print "UDP:", u$id$orig_h, u$id$orig_p, u$id$resp_h, u$id$resp_p;
	}

# @TEST-START-FILE my-ethernet.spicy
module MyEthernet;

import zeek;

public type Packet = unit {
    ethernet: bytes &size=14;

    on %done {
        zeek::forward_packet(0x0800); # in practice, this wouldn't be hardcoded of course;
    }
};
# @TEST-END-FILE

# @TEST-START-FILE my-ethernet.evt
packet analyzer spicy::MyEthernet:
    parse with MyEthernet::Packet,
    replaces Ethernet;

on MyEthernet::Packet -> event MyEthernet::data($packet, self.ethernet);
# @TEST-END-FILE
