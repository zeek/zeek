# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dns-binds.pcap %INPUT > output
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: btest-diff output

@load policy/protocols/dns/auth-addl

event dns_BINDS(c: connection, msg: dns_msg, ans: dns_answer, binds: dns_binds_rr)
	{
	print "BINDS", binds;
	}
