# @TEST-DOC: Test basic parsing of IGMP traffic
#
# Calling sort here is because events are coming out in different orders on
# different platforms, and this forces them to be consistent.
# @TEST-EXEC: zeek -r $TRACES/igmp/igmp.pcap %INPUT | sort > out
# @TEST-EXEC: zeek -r $TRACES/igmp/multicast-igmp-version-membership-query-and-report.pcap %INPUT | sort >> out
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out

@load base/packet-protocols/igmp/types

event IGMP::message(packet: raw_pkt_hdr, msg_type: IGMP::MessageType) {
	print network_time(), "IGMP::message", packet, msg_type;
}

event IGMP::membership_query(source: addr, group_addr: addr) {
	print network_time(), "IGMP::membership_query", source, group_addr;
}

event IGMP::membership_report_v2(source: addr, group_addr: addr) {
	print network_time(), "IGMP::membership_report_v2", source, group_addr;
}

event IGMP::leave_group(source: addr, group_addr: addr) {
	print network_time(), "IGMP::leave_group", source, group_addr;
}

event IGMP::membership_report_v3(source: addr, groups: vector of IGMP::Group) {
	print network_time(), "IGMP::membership_report_v3", source, groups;
}
