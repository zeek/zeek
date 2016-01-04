##! Log memory/packet/lag statistics.  Differs from
##! :doc:`/scripts/policy/misc/profiling.bro` in that this
##! is lighter-weight (much less info, and less load to generate).

@load base/frameworks/notice

module Stats;

export {
	redef enum Log::ID += { LOG };

	## How often stats are reported.
	const stats_report_interval = 5min &redef;

	type Info: record {
		## Timestamp for the measurement.
		ts:            time      &log;
		## Peer that generated this log.  Mostly for clusters.
		peer:          string    &log;
		## Amount of memory currently in use in MB.
		mem:           count     &log;
		## Number of packets processed since the last stats interval.
		pkts_proc:     count     &log;
		## Number of events processed since the last stats interval.
		events_proc:   count     &log;
		## Number of events that have been queued since the last stats
		## interval.
		events_queued: count     &log;

		## TCP connections seen since last stats interval.
		tcp_conns: count     &log;
		## UDP connections seen since last stats interval.
		udp_conns: count     &log;
		## ICMP connections seen since last stats interval.
		icmp_conns: count    &log;

		## Current size of TCP data in reassembly.
		reassem_tcp_size: count &log;
		## Current size of File data in reassembly.
		reassem_file_size: count &log;
		## Current size of packet fragment data in reassembly.
		reassem_frag_size: count &log;
		## Current size of unkown data in reassembly (this is only PIA buffer right now).
		reassem_unknown_size: count &log;

		## Lag between the wall clock and packet timestamps if reading
		## live traffic.
		lag:           interval  &log &optional;
		## Number of packets received since the last stats interval if
		## reading live traffic.
		pkts_recv:     count     &log &optional;
		## Number of packets dropped since the last stats interval if
		## reading live traffic.
		pkts_dropped:  count     &log &optional;
		## Number of packets seen on the link since the last stats
		## interval if reading live traffic.
		pkts_link:     count     &log &optional;
		## Number of bytes received since the last stats interval if
		## reading live traffic.
		bytes_recv:   count     &log &optional;
	};

	## Event to catch stats as they are written to the logging stream.
	global log_stats: event(rec: Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(Stats::LOG, [$columns=Info, $ev=log_stats, $path="stats"]);
	}

event check_stats(last_ts: time, last_ns: NetStats, last_res: bro_resources)
	{
	local now = current_time();
	local ns = net_stats();
	local res = resource_usage();

	if ( bro_is_terminating() )
		# No more stats will be written or scheduled when Bro is
		# shutting down.
		return;

	local info: Info = [$ts=now, 
	                    $peer=peer_description,
	                    $mem=res$mem/1000000,
	                    $pkts_proc=res$num_packets - last_res$num_packets,
	                    $events_proc=res$num_events_dispatched - last_res$num_events_dispatched,
	                    $events_queued=res$num_events_queued - last_res$num_events_queued,
	                    $tcp_conns=res$cumulative_tcp_conns - last_res$cumulative_tcp_conns, 
	                    $udp_conns=res$cumulative_udp_conns - last_res$cumulative_udp_conns,
	                    $icmp_conns=res$cumulative_icmp_conns - last_res$cumulative_icmp_conns,
	                    $reassem_tcp_size=res$reassem_tcp_size,
	                    $reassem_file_size=res$reassem_file_size,
	                    $reassem_frag_size=res$reassem_frag_size,
	                    $reassem_unknown_size=res$reassem_unknown_size
	                    ];

	# Someone's going to have to explain what this is and add a field to the Info record.
	# info$util = 100.0*((res$user_time + res$system_time) - (last_res$user_time + last_res$system_time))/(now-last_ts);

	if ( reading_live_traffic() )
		{
		info$lag = now - network_time();
		info$pkts_recv = ns$pkts_recvd - last_ns$pkts_recvd;
		info$pkts_dropped = ns$pkts_dropped  - last_ns$pkts_dropped;
		info$pkts_link = ns$pkts_link  - last_ns$pkts_link;
		info$bytes_recv = ns$bytes_recvd  - last_ns$bytes_recvd;
		}

	Log::write(Stats::LOG, info);
	schedule stats_report_interval { check_stats(now, ns, res) };
	}

event bro_init()
	{
	schedule stats_report_interval { check_stats(current_time(), net_stats(), resource_usage()) };
	}
