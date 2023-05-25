# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o my-ethernet.hlto my-ethernet.spicy my-ethernet.evt
# @TEST-EXEC: zeek -r ${TRACES}/dns53.pcap my-ethernet.hlto %INPUT ENABLE=T >output-on
# @TEST-EXEC: zeek -r ${TRACES}/dns53.pcap my-ethernet.hlto %INPUT ENABLE=F >output-off
# @TEST-EXEC: btest-diff output-on

#
# @TEST-DOC: Check that we can replace Zeek's Ethernet analyzer.
#
# Zeek logs look the same in both cases but we get some additional output
# when our analyzer is running by raising a custom event.

const ENABLE = T &redef;

module MyEthernet;

const DLT_EN10MB : count = 1;

event zeek_init() &priority=-200
	{
	if ( ENABLE )
		Spicy::enable_file_analyzer(PacketAnalyzer::ANALYZER_SPICY_MYETHERNET);
	else
		Spicy::disable_file_analyzer(PacketAnalyzer::ANALYZER_SPICY_MYETHERNET);
}

# The priority here needs to be higher than the standard script registering the
# built-in Ethernet analyzer.
event zeek_init() &priority=-100
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_EN10MB, PacketAnalyzer::ANALYZER_SPICY_MYETHERNET);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_SPICY_MYETHERNET, 0x0800, PacketAnalyzer::ANALYZER_IP);
	}

event MyEthernet::data(p: raw_pkt_hdr, data: string)
	{
	print "My Ethernet:", data;
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
