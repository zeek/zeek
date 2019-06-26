# @TEST-EXEC: zeek -r $TRACES/dns-huge-ttl.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	print ans;
	}
