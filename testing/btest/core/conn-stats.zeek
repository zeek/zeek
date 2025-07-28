# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: zeek -b -r $TRACES/dns-edns-ecs.pcap %INPUT
# @TEST-EXEC: zeek -b -r $TRACES/contentline-irc-5k-line.pcap %INPUT
#
# @TEST-EXEC: btest-diff .stdout

event zeek_init()
	{
	print fmt("pcap %s", split_string(packet_source()$path, /\//)[-1]);
	}

event net_done(t: time)
	{
	print get_conn_stats();
	}
