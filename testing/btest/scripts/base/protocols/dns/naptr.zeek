# @TEST-EXEC: zeek -b -r $TRACES/dns/naptr.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: zeek-cut -m uid query qclass_name qtype_name answers < dns.log > dns.log.cut
# @TEST-EXEC: btest-diff dns.log.cut

@load base/protocols/dns

event dns_NAPTR_reply(c: connection, msg: dns_msg, ans: dns_answer, naptr: dns_naptr_rr)
	{
	print "NAPTR", msg, ans, naptr;
	}
