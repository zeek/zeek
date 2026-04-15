# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dns-edns-bad-length.pcap %INPUT > output
# @TEST-EXEC: test ! -s output
# @TEST-EXEC: grep -q 'EDNS_truncated_option' weird.log
# @TEST-EXEC: test "$(grep -c 'EDNS_truncated_option' weird.log)" = "1"

@load base/frameworks/notice/weird
@load base/protocols/dns

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	print "A", a;
	}
