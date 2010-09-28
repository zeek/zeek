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

global last_stats_time = current_time();
global last_stats_CPU_time =
	resource_usage()$user_time + resource_usage()$system_time;

# Global to store the last net_stats object received.
global last_packet_stat: net_stats;

# Globals to store the results between reporting intervals
global stat_packets_received = 0;
global stat_packets_dropped = 0;
global stat_packets_link = 0;

global last_packets_processed = 0;
global last_events_dispatched = 0;
global last_events_queued = 0;

# Interval in which the results are sent as a notice.  If this is less
# than heartbeat_interval, then it is set to heartbeat_interval, since
# some of the reported statistics are only gathered via the heartbeat.
global stats_report_interval = 10 sec &redef;

event check_stats()
	{
	local now = current_time();
	local lag = now - network_time();
	local report_delta = now - last_stats_time;

	local res = resource_usage();
	local mem = res$mem;
	local total_CPU_time = res$user_time + res$system_time;
	local CPU_util = (total_CPU_time - last_stats_CPU_time) / report_delta;

	if ( bro_is_terminating() )
		# No more stats will be written or scheduled when Bro is
		# shutting down.
		return;

	local delta_pkts_processed = res$num_packets - last_packets_processed;
	local delta_events = res$num_events_dispatched - last_events_dispatched;
	local delta_queued = res$num_events_queued - last_events_queued;

	local stat_msg =
		fmt("mem=%dMB pkts_proc=%d events_proc=%d events_queued=%d",
			mem / 1000000, delta_pkts_processed,
			delta_events, delta_queued);

	if ( reading_live_traffic() )
		{
		stat_msg = fmt("%s et=%.2f lag=%fsec util=%.01f%% pkts_rcv=%d pkts_drp=%d pkts_link=%d",
				stat_msg, report_delta, lag, CPU_util * 100.0,
				stat_packets_received, stat_packets_dropped,
				stat_packets_link);
		NOTICE([$note=ResourceStats, $msg=stat_msg]);
		}

	else if ( reading_traces() )
		NOTICE([$note=OfflineResourceStats, $msg=stat_msg]);

	else
		{
		# Remote communication only.
		stat_msg = fmt("mem=%dMB events_proc=%d events_queued=%d lag=%fsec util=%.01f%%",
				mem / 1000000, delta_events, delta_queued,
				lag, CPU_util * 100.0 );
		NOTICE([$note=ResourceStats, $msg=stat_msg]);
		}

	last_stats_time = now;
	last_stats_CPU_time = total_CPU_time;
	last_packets_processed = res$num_packets;
	last_events_dispatched = res$num_events_dispatched;
	last_events_queued = res$num_events_queued;

	stat_packets_received = 0;
	stat_packets_dropped = 0;

	schedule stats_report_interval { check_stats() };
	}

event net_stats_update(t: time, ns: net_stats)
	{
	if ( ns$pkts_recvd > last_packet_stat$pkts_recvd )
		stat_packets_received +=
			ns$pkts_recvd - last_packet_stat$pkts_recvd;

	if ( ns$pkts_dropped > last_packet_stat$pkts_dropped )
		stat_packets_dropped +=
			ns$pkts_dropped - last_packet_stat$pkts_dropped;

	if ( ns$pkts_link > last_packet_stat$pkts_link )
		stat_packets_link += ns$pkts_link - last_packet_stat$pkts_link;

	last_packet_stat = ns;
	}

event start_check_stats()
	{
	# Can't start reporting data until network_time() is up.
	local zero_time: time = 0;

	if ( network_time() > zero_time )
		schedule stats_report_interval { check_stats() };
	else
		schedule stats_report_interval { start_check_stats() };
	}

event bro_init()
	{
	last_packet_stat$pkts_recvd = last_packet_stat$pkts_dropped =
		last_packet_stat$pkts_link = 0;

	if ( stats_report_interval < heartbeat_interval )
		stats_report_interval = heartbeat_interval;

	schedule stats_report_interval { start_check_stats() };
	}
