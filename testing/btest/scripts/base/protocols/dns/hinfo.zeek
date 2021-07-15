# @TEST-EXEC: zeek -b -r $TRACES/dns/hinfo.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/dns

event dns_HINFO_reply(c: connection, msg: dns_msg, ans: dns_answer, cpu: string, os: string)
	{
	print "HINFO", msg, ans, cpu, os;
	}
