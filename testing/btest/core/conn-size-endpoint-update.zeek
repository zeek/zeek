# @TEST-DOC: Ensure that a connection's orig and resp records have up-to-date data


# @TEST-EXEC: zeek -b -r $TRACES/tcp/syn.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -r $TRACES/tcp/synack.pcap %INPUT >> out
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >> out
#
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print "==== zeek_init", split_string(packet_source()$path, /\//)[-1];
	}

event new_connection(c: connection)
	{
	print "new_connection", c$uid;
	print "  orig", c$orig;
	print "  resp", c$resp;
	}

event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	print "connection_SYN_packet", c$uid, pkt$is_orig ? "orig" : "resp";
	print "  orig", c$orig;
	print "  resp", c$resp;
	}

event connection_established(c: connection)
	{
	print "connection_established", c$uid;
	print "  orig", c$orig;
	print "  resp", c$resp;
	}

event connection_state_remove(c: connection)
	{
	print "connection_state_remove", c$uid;
	print "  orig", c$orig;
	print "  resp", c$resp;
	}
