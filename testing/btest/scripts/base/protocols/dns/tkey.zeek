# @TEST-EXEC: zeek -b -C -r $TRACES/dns/tkey.pcap %INPUT > output
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/dns

redef dns_skip_all_addl = F;

event dns_TKEY(c: connection, msg: dns_msg, ans: dns_tkey)
	{
	print "TKEY";
	print "query", ans$query;
	print "qtype", ans$qtype;
	print "alg_name", ans$alg_name;
	print "inception", ans$inception;
	print "expiration", ans$expiration;
	print "mode", ans$mode;
	print "rr_error", ans$rr_error;
	print "key_data size", |ans$key_data|;
	print "is_query", ans$is_query;
	}
