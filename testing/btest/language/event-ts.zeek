# @TEST-EXEC: zeek -b -r $TRACES/ticks-dns.pcap %INPUT > out
# @TEST-EXEC: btest-diff out

# Note: We use a PCAP with DNS queries only so that we have a single packet per
# time step. Thus the run loop will be executed only once per time step.

global runs = -1;

event test(depth: count)
	{
	if ( depth == 0 )
		return;

	print fmt("[%D] Test %s was scheduled at %D", network_time(), depth, current_event_time());
	event test(--depth);
	}

event new_connection(c: connection)
	{
	print fmt(">> Run %s (%D):", ++runs, network_time());
	# Descend into recursion to enqueue events until we add an event that will
	# be handled in the next run loop iteration, i.e. at a different timestamp
	# than it was enqueued. Use four levels of recursion as every drain of the
	# event queue handles two layers and the event queue is drained two times.
	# First after processing a packet and second in the run loop. Finally, we
	# expect an event so that network_time() > current_event_time().
	event test(4);
	}
