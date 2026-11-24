# @TEST-DOC: Ensure a raw_pkt_hdr created from a VXLAN inner packet includes l2 information. Regression test for #6103
#
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/vxlan-encapsulated-igmp-v2.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff out

@load base/frameworks/tunnels

event IGMP::message(p: raw_pkt_hdr, msg_type: IGMP::MessageType)
	{
	print "IGMP::message", p$l2;
	}
