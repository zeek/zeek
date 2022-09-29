# @TEST-DOC: Add a packet analyzer to Analyzer::disabled_analyzers and ensure it does not generate events (vxlan in this case).
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/vxlan.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
#

# Removing this line triggers vxlan events from all but the first two packets.
redef Analyzer::disabled_analyzers += { PacketAnalyzer::ANALYZER_VXLAN };

global all_packets = 0;

event raw_packet(hdr: raw_pkt_hdr)
	{
	++all_packets;
	print "packet", all_packets;
	}

# Should never run.
event vxlan_packet(outer: connection, inner: pkt_hdr, vni: count)
	{
	print "vxlan_packet", outer$uid, "inner", inner$ip;
	}
