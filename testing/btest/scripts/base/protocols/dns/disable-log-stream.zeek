# @TEST-DOC: Disable the DNS log stream and verify that c$dns and c$dns_state is not put on the connection.
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dns-binds.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test ! -f dns.log

@load base/protocols/dns

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) &priority=5
	{
	print "dns_message", c$uid, "has dns", c?$dns, "has dns_state", c?$dns_state;
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	print "dns_request", c$uid, "has dns", c?$dns, "has dns_state", c?$dns_state;
	}

event zeek_init()
	{
	if ( ! Log::disable_stream(DNS::LOG) )
		exit(1);
	}
