# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace %INPUT > output
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

event scheduled_delayed_event()
	{
	print fmt("scheduled_delayed_event: %T", network_time());
	}

event scheduled_event()
	{
	print fmt("scheduled_event:         %T", network_time());
	schedule 1sec { scheduled_delayed_event() };
	}

event zeek_init()
	{
	print fmt("zeek_init:               %T", network_time());
	schedule 0sec { scheduled_event() };
	}

event network_time_init()
	{
	print fmt("network_time_init:       %T", network_time());
	}

global pkt_count: count = 0;

event new_packet(c: connection, p: pkt_hdr) &priority=10
	{
	pkt_count += 1;
	if ( pkt_count % 25 == 0 )
		print fmt("Processing packet  %s at %T", pkt_count, network_time());

	if ( pkt_count == 100)
		terminate();
	}
