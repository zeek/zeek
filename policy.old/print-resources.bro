# $Id: print-resources.bro 6703 2009-05-13 22:27:44Z vern $

# Logs Bro resource usage information upon termination.

@load notice

redef enum Notice += {
	ResourceSummary,	# Notice type for this event
};
 
event bro_done()
	{
	local res = resource_usage();
	
	NOTICE([$note=ResourceSummary,
		$msg=fmt("elapsed time = %s, total CPU = %s, maximum memory = %d KB, peak connections = %d, peak timers = %d, peak fragments = %d",
		res$real_time, res$user_time + res$system_time,
		res$mem / 1024,
		res$max_TCP_conns + res$max_UDP_conns + res$max_ICMP_conns,
		res$max_timers, res$max_fragments)]);
	}
