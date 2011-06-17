# $Id: stats.bro 4011 2007-02-28 07:01:12Z vern $

# Track memory/lag statistics.  Differs from profiling.bro in that this
# is lighter-weight (much less info, and less load to generate).

@load notice

redef enum Notice += {
	ResourceStats,		# generated when running live packet capture
	OfflineResourceStats,	# generated when reading trace files
};

# ResourceStats should by default be sent to the notice file
redef notice_action_filters += {
	[[ResourceStats, OfflineResourceStats]] = file_notice
};

# Interval in which the results are sent as a notice.  If this is less
# than heartbeat_interval, then it is set to heartbeat_interval, since
# some of the reported statistics are only gathered via the heartbeat.
global stats_report_interval = 10 sec &redef;

event check_stats(last_time: time, last_ns: NetStats, last_res: bro_resources)
	{
	local now = current_time();
	local lag = now - network_time();
	local report_delta = now - last_time;

	local res = resource_usage();
	local ns = net_stats();
	
	local total_CPU_time = res$user_time + res$system_time;
	local last_CPU_time = last_res$user_time + last_res$system_time;
	local CPU_util = ((total_CPU_time - last_CPU_time) / report_delta) * 100.0;
	
	local pkts_recvd    = ns$pkts_recvd   - last_ns$pkts_recvd;
	local pkts_dropped  = ns$pkts_dropped - last_ns$pkts_dropped;
	local pkts_link     = ns$pkts_link    - last_ns$pkts_link;

	if ( bro_is_terminating() )
		# No more stats will be written or scheduled when Bro is
		# shutting down.
		return;

	local delta_pkts_processed = res$num_packets - last_res$num_packets;
	local delta_events = res$num_events_dispatched - last_res$num_events_dispatched;
	local delta_queued = res$num_events_queued - last_res$num_events_queued;

	local stat_msg =
		fmt("mem=%dMB pkts_proc=%d events_proc=%d events_queued=%d",
			res$mem / 1000000, delta_pkts_processed,
			delta_events, delta_queued);

	if ( reading_live_traffic() )
		{
		stat_msg = fmt("%s et=%.2f lag=%fsec util=%.01f%% pkts_rcv=%d pkts_drp=%d pkts_link=%d",
				stat_msg, report_delta, lag, CPU_util,
				pkts_recvd, pkts_dropped, pkts_link);
		NOTICE([$note=ResourceStats, $msg=stat_msg]);
		}

	else if ( reading_traces() )
		NOTICE([$note=OfflineResourceStats, $msg=stat_msg]);

	else
		{
		# Remote communication only.
		stat_msg = fmt("mem=%dMB events_proc=%d events_queued=%d lag=%fsec util=%.01f%%",
				res$mem / 1000000, delta_events, delta_queued,
				lag, CPU_util);
		NOTICE([$note=ResourceStats, $msg=stat_msg]);
		}

	print "did stats!";
	schedule stats_report_interval { check_stats(now, ns, res) };
	}

event bro_init()
	{
	schedule stats_report_interval { check_stats(current_time(), net_stats(), resource_usage()) };
	}
