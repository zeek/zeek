# @TEST-EXEC: zeek -b -C -r $TRACES/dnssec/dnskey.pcap %INPUT > output
# @TEST-EXEC: zeek -b -C -r $TRACES/dnssec/dnskey2.pcap %INPUT >> output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

@load base/protocols/dns

event zeek_init()
	{
	print "===", packet_source()$path;
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	print c$uid, "is_orig", is_orig, "QR", msg$QR, "AD", msg$AD, "CD", msg$CD;
	}
