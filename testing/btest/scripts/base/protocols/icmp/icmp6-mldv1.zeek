# @TEST-DOC: Tests processing of IPv6 MLD v1 messages.
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp6-mldv1.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

event icmpv6_mld_report_v1(c: connection, group_addr: addr)
	{
	print "icmpv6_mld_report_v1", c$id$orig_h, group_addr;
	}

event icmpv6_mld_done_v1(c: connection, group_addr: addr)
	{
	print "icmpv6_mld_done_v1", c$id$orig_h, group_addr;
	}
