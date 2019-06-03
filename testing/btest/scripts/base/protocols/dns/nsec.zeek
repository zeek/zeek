# @TEST-EXEC: zeek -C -r $TRACES/dnssec/nsec.pcap %INPUT > output
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: btest-diff output

@load policy/protocols/dns/auth-addl

event dns_RRSIG(c: connection, msg: dns_msg, ans: dns_answer, rrsig: dns_rrsig_rr)
	{
	print "RRSIG", rrsig, bytestring_to_hexstr(rrsig$signature);
	}

event dns_DNSKEY(c: connection, msg: dns_msg, ans: dns_answer, dnskey: dns_dnskey_rr)
	{
	print "DNSKEY", dnskey, bytestring_to_hexstr(dnskey$public_key);
	}

event dns_NSEC(c: connection, msg: dns_msg, ans: dns_answer, next_name: string, bitmaps: string_vec)
	{
	print "NSEC", next_name, bitmaps;

	for ( i in bitmaps )
		print bytestring_to_hexstr(bitmaps[i]);
	}

event dns_NSEC3(c: connection, msg: dns_msg, ans: dns_answer, nsec3: dns_nsec3_rr)
	{
	print "NSEC3", nsec3,
	      bytestring_to_hexstr(nsec3$nsec_salt),
	      bytestring_to_hexstr(nsec3$nsec_hash);
	}

event dns_DS(c: connection, msg: dns_msg, ans: dns_answer, ds: dns_ds_rr)
	{
	print "DS", ds, bytestring_to_hexstr(ds$digest_val);
	}
