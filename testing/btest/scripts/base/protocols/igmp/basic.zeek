# @TEST-DOC: Test basic parsing of IGMPv3 traffic
#
# @TEST-EXEC: zeek -r $TRACES/igmp/igmp.pcap %INPUT > out
# @TEST-EXEC: btest-diff igmp.log
# @TEST-EXEC: btest-diff out

@load base/packet-protocols/igmp/types

event IGMP::message(packet: raw_pkt_hdr, msg_type: IGMP::MessageType) {
	print "IGMP::message", packet, msg_type;
}

event IGMP::membership_query(packet: raw_pkt_hdr, group_addr: addr) {
	print "IGMP::membership_query", packet, group_addr;
}

event IGMP::membership_report_v2(packet: raw_pkt_hdr, group_addr: addr) {
	print "IGMP::membership_report_v2", packet, group_addr;
}

event IGMP::leave_group(packet: raw_pkt_hdr, group_addr: addr) {
	print "IGMP::leave_group", packet, group_addr;
}

event IGMP::membership_report_v3(packet: raw_pkt_hdr, num_groups: count, groups: vector of IGMP::Group) {
	print "IGMP::membership_report_v3", packet, num_groups, groups;
}
