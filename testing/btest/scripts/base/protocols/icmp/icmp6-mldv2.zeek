# @TEST-DOC: Tests processing of IPv6 MLD v2 messages.
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp6-mldv2.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff weird.log

@load base/frameworks/notice/weird

event icmpv6_mld_report_v2(c: connection, groups: icmp6_mldv2_mar_vector)
{
	print c$id$orig_h, groups;
}
