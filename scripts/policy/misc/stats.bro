##! Log memory/packet/lag statistics.  Differs from
##! :doc:`/scripts/policy/misc/profiling.bro` in that this
##! is lighter-weight (much less info, and less load to generate).

@load base/frameworks/notice

module Stats;

export {
	redef enum Log::ID += { LOG };

	## How often stats are reported.
	const stats_report_interval = 1min &redef;

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
	};

	## Event to catch stats as they are written to the logging stream.
	global log_stats: event(rec: Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(Stats::LOG, [$columns=Info, $ev=log_stats]);
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

	local info: Info = [$ts=now, $peer=peer_description, $mem=res$mem/1000000,
	                    $pkts_proc=res$num_packets - last_res$num_packets,
	                    $events_proc=res$num_events_dispatched - last_res$num_events_dispatched,
	                    $events_queued=res$num_events_queued - last_res$num_events_queued];

	if ( reading_live_traffic() )
		{
		info$lag = now - network_time();
		# Someone's going to have to explain what this is and add a field to the Info record.
		# info$util = 100.0*((res$user_time + res$system_time) - (last_res$user_time + last_res$system_time))/(now-last_ts);
		info$pkts_recv = ns$pkts_recvd - last_ns$pkts_recvd;
		info$pkts_dropped = ns$pkts_dropped  - last_ns$pkts_dropped;
		info$pkts_link = ns$pkts_link  - last_ns$pkts_link;
		}

	Log::write(Stats::LOG, info);
	schedule stats_report_interval { check_stats(now, ns, res) };
	}

event bro_init()
	{
	schedule stats_report_interval { check_stats(current_time(), net_stats(), resource_usage()) };
	}
