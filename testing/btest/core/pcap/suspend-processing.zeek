# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff .stderr

redef exit_only_after_terminate = T;

event go_on()
	{
	continue_processing();
	print fmt("network_time: %f", network_time());
	}

event pcap_init()
	{
	print fmt("network_time: %f", network_time());
	suspend_processing();
	# Some asynchronous work
	schedule 5sec { go_on() };
	}

event zeek_init()
	{
	schedule 0sec { pcap_init() };
	}

global pkt_cnt: count = 0;

event new_packet(c: connection, p: pkt_hdr)
	{
	pkt_cnt += 1;
	print fmt("Processing packet %s at %f", pkt_cnt, network_time());
	if ( pkt_cnt >= 20 )
		terminate();
	}
