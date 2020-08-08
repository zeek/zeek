# @TEST-EXEC: zeek -b -r $TRACES/dns-caa.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/dns

event dns_CAA_reply(c: connection, msg: dns_msg, ans: dns_answer, flags: count, tag: string, value: string)
	{
	print flags,tag,value;
	}
