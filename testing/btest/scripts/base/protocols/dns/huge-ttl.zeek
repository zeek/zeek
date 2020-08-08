# @TEST-EXEC: zeek -b -r $TRACES/dns-huge-ttl.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/dns

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	print ans;
	}
