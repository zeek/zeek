# @TEST-DOC: Test that a WKS RR doesn't cause an evasion of later RRs
# @TEST-EXEC: zeek -b -r $TRACES/dns/wks_rr.pcap %INPUT > out
# @TEST-EXEC: btest-diff out

@load base/protocols/dns

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	print "A";
	}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	print "WKS";
	}
