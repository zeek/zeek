# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dns-wks.pcap %INPUT > output
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: btest-diff output

@load policy/protocols/dns/auth-addl

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	print "WKS", dns_msg, dns_answer;
	}
