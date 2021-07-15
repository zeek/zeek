# @TEST-EXEC: zeek -b -C -r $TRACES/dnssec/nsec3param.pcap %INPUT > output
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: btest-diff output

@load policy/protocols/dns/auth-addl

event dns_NSEC3PARAM(c: connection, msg: dns_msg, ans: dns_answer, nsec3param: dns_nsec3param_rr)
	{
	print "NSEC3PARAM", nsec3param,
	      bytestring_to_hexstr(nsec3param$nsec_salt);
	}
