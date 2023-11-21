# @TEST-DOC: Add the textual representation of the DNSSEC algorithm into answers and verify there's no weirds for the ed25519 and ed448 curves.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnssec/ed25519.no.pcap %INPUT
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: zeek-cut -m id.orig_h id.resp_h qtype_name query answers < dns.log > dns.ed25519.log
#
# @TEST-EXEC: zeek -b -C -r $TRACES/dnssec/ed448.no.pcap %INPUT
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: zeek-cut -m id.orig_h id.resp_h questions answers < dns.log > dns.ed448.log
#
# @TEST-EXEC: btest-diff dns.ed25519.log
# @TEST-EXEC: btest-diff dns.ed448.log

@load base/protocols/dns

event dns_RRSIG(c: connection, msg: dns_msg, ans: dns_answer, rrsig: dns_rrsig_rr) &priority=4
	{
	c$dns$answers += DNS::algorithms[rrsig$algorithm];
	}

event dns_DNSKEY(c: connection, msg: dns_msg, ans: dns_answer, dnskey: dns_dnskey_rr) &priority=4
	{
	c$dns$answers += DNS::algorithms[dnskey$algorithm];
	}
