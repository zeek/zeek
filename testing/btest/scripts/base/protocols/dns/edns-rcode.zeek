# @TEST-DOC: Tests that the correct extended rcode is returned for EDNS packets. Regression test for #4656.
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dns_extended_rcode.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

@load base/protocols/dns

redef dns_skip_all_addl=F;

event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
	{
	if ( c$dns?$rcode && ans?$extended_rcode )
		print ans$extended_rcode;
	}
