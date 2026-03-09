# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace %INPUT > output
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

global sde_init: bool = F;

event scheduled_delayed_event()
	{
	if ( ! sde_init )
		{
		# When network_time is set we (usually) leap forward and the event
		# fires with the first packet. Thus, we reschedule.
		sde_init = T;
		schedule 2sec { scheduled_delayed_event() };
		}
	else
		{
		print fmt("scheduled_delayed_event: %T", network_time());
		}
	}

event scheduled_event()
	{
	# This event is immediately executed
	print fmt("scheduled_event:         %T", network_time());
	}

event zeek_init()
	{
	# Reading a PCAP network_time is not initialized yet
	print fmt("zeek_init:               %T", network_time());
	schedule 0sec { scheduled_event() };
	schedule 2sec { scheduled_delayed_event() };
	}

event network_time_init()
	{
	# This event is executed when network_time is initialized
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
