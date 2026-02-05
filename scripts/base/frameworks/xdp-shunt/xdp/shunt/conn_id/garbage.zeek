module XDP::Shunt::ConnID;

export {
	## Event raised which triggers garbage collection
	global collect_garbage: event(xdp_prog: opaque of XDP::Program,
	    timeout_interval: interval);

	## How frequently to run garbage collection
	option collection_interval: interval = 10sec;

	## After how long with no activity should a shunted connection get unshunted?
	option timeout_interval: interval = 10sec;

	## Whether to enable auto-rescheduling garbage collection. You may still trigger
	## garbage collection passes manually with the collect_garbage event.
	option enable_gc: bool = F;
}

event collect_garbage(xdp_prog: opaque of XDP::Program,
    timeout_interval: interval)
	{
	_collect_garbage(xdp_prog, timeout_interval);

	# Only reschedule if the user enabled GC. Otherwise they will manage it by
	# themselves.
	if ( enable_gc )
		schedule collection_interval { XDP::Shunt::ConnID::collect_garbage(
		    XDP::xdp_prog, timeout_interval) };
	}

event network_time_init()
	{
	# Use the option for the initial schedule, users may choose to schedule themselves
	# with enable_gc false
	if ( enable_gc )
		schedule collection_interval { XDP::Shunt::ConnID::collect_garbage(
		    XDP::xdp_prog, timeout_interval) };
	}
