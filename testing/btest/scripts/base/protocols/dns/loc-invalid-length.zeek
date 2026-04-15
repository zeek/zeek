# @TEST-EXEC: zeek -b -C -r $TRACES/dns/loc-invalid-length.pcap %INPUT > output
# @TEST-EXEC: test ! -s output
# @TEST-EXEC: grep -q 'dns_invalid_loc_length' weird.log
# @TEST-EXEC: test "$(grep -c 'dns_invalid_loc_length' weird.log)" = "1"

@load base/frameworks/notice/weird
@load base/protocols/dns

event dns_LOC(c: connection, msg: dns_msg, ans: dns_answer, loc: dns_loc_rr)
	{
	print "LOC", loc;
	}
