# @TEST-EXEC: zeek -b -r $TRACES/tcp/syn.pcap %INPUT > syn.out
# @TEST-EXEC: zeek -b -r $TRACES/tcp/syn-synack.pcap %INPUT > syn-synack.out
# @TEST-EXEC: zeek -b -r $TRACES/tcp/no-handshake.pcap %INPUT > no-handshake.out
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT > http.out
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-ping.pcap %INPUT > icmp.out
# @TEST-EXEC: zeek -b -r $TRACES/dns53.pcap %INPUT > udp.out

# @TEST-EXEC: btest-diff syn.out
# @TEST-EXEC: btest-diff syn-synack.out
# @TEST-EXEC: btest-diff no-handshake.out
# @TEST-EXEC: btest-diff http.out
# @TEST-EXEC: btest-diff icmp.out
# @TEST-EXEC: btest-diff udp.out

event connection_successful(c: connection)
	{
	print "connection_successful", c$successful;
	}

event connection_established(c: connection)
	{
	print "connection_established", c$successful;
	}

event connection_state_remove(c: connection)
	{
	print "connection_state_remove", c$successful;
	}

event successful_connection_remove(c: connection)
	{
	print "successful_connection_remove", c$successful;
	}
