# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -o analyzer.hlto analyzer.spicy analyzer.evt
# @TEST-EXEC: zeek -r ${TRACES}/spicy/packet-analyzer-stale-packet.pcap analyzer.hlto %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: $packet must reflect the current frame after a preceding %error event.

# @TEST-START-FILE analyzer.spicy
module Test;

public type Frame = unit {
    b: uint8 {
        if ($$ == 0xFF)
            throw "bad frame";
    }
};
# @TEST-END-FILE

# @TEST-START-FILE analyzer.evt
packet analyzer spicy::TEST:
    parse with Test::Frame;

on Test::Frame -> event Test::frame($packet);
on Test::Frame::%error -> event Test::failed($packet);
# @TEST-END-FILE

event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x6666, "spicy_TEST") )
		print "cannot register spicy analyzer";
	}

event Test::frame(pkt: raw_pkt_hdr)
	{
	print fmt("frame src=%s", pkt$l2$src);
	}

event Test::failed(pkt: raw_pkt_hdr)
	{
	print fmt("error src=%s", pkt$l2$src);
	}
