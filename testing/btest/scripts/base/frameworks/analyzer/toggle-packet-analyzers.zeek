# @TEST-DOC: Use Analyzer::disable_analyzer() and Analyzer::enable_analyzer() to disable the VXLAN packet analyzers at runtime based on total raw packet count.
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/vxlan.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
#

global all_packets = 0;

event raw_packet(hdr: raw_pkt_hdr)
	{
	++all_packets;
	print "packet", all_packets;

	if ( all_packets == 4 )
		{
		local er = Analyzer::disable_analyzer(PacketAnalyzer::ANALYZER_VXLAN);
		print "Analyzer::disable_analyzer(PacketAnalyzer::ANALYZER_VXLAN)", er;
		}
	# Packets 5 to 8 don't produce vxlan_packet events.

	if ( all_packets == 8 )
		{
		local dr = Analyzer::enable_analyzer(PacketAnalyzer::ANALYZER_VXLAN);
		print "Analyzer::enable_analyzer(PacketAnalyzer::ANALYZER_VXLAN)", dr;
		}
	}

event vxlan_packet(outer: connection, inner: pkt_hdr, vni: count)
	{
	print "vxlan_packet", outer$uid, "inner", inner$ip;
	}
