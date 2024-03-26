##! Log memory/packet/lag statistics.

@load base/frameworks/notice
@load base/frameworks/telemetry

module Stats;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## How often stats are reported.
	option report_interval = 5min;

	type Info: record {
		## Timestamp for the measurement.
		ts:            time      &log;
		## Peer that generated this log.  Mostly for clusters.
		peer:          string    &log;
		## Amount of memory currently in use in MB.
		mem:           count     &log;
		## Number of packets processed since the last stats interval.
		pkts_proc:     count     &log;
		## Number of bytes received since the last stats interval if
		## reading live traffic.
		bytes_recv:    count     &log;

		## Number of packets dropped since the last stats interval if
		## reading live traffic.
		pkts_dropped:  count     &log &optional;
		## Number of packets seen on the link since the last stats
		## interval if reading live traffic.
		pkts_link:     count     &log &optional;
		## Lag between the wall clock and packet timestamps if reading
		## live traffic.
		pkt_lag:       interval  &log &optional;
		## Number of packets filtered from the link since the last
		## stats interval if reading live traffic.
		pkts_filtered: count     &log &optional;

		## Number of events processed since the last stats interval.
		events_proc:   count     &log;
		## Number of events that have been queued since the last stats
		## interval.
		events_queued: count     &log;

		## TCP connections currently in memory.
		active_tcp_conns: count  &log;
		## UDP connections currently in memory.
		active_udp_conns: count &log;
		## ICMP connections currently in memory.
		active_icmp_conns: count &log;

		## TCP connections seen since last stats interval.
		tcp_conns:        count  &log;
		## UDP connections seen since last stats interval.
		udp_conns:        count &log;
		## ICMP connections seen since last stats interval.
		icmp_conns:        count &log;

		## Number of timers scheduled since last stats interval.
		timers: count &log;
		## Current number of scheduled timers.
		active_timers: count &log;

		## Number of files seen since last stats interval.
		files: count &log;
		## Current number of files actively being seen.
		active_files: count &log;

		## Number of DNS requests seen since last stats interval.
		dns_requests: count &log;
		## Current number of DNS requests awaiting a reply.
		active_dns_requests: count &log;

		## Current size of TCP data in reassembly.
		reassem_tcp_size: count &log;
		## Current size of File data in reassembly.
		reassem_file_size: count &log;
		## Current size of packet fragment data in reassembly.
		reassem_frag_size: count &log;
		## Current size of unknown data in reassembly (this is only PIA buffer right now).
		reassem_unknown_size: count &log;
	};

	## Event to catch stats as they are written to the logging stream.
	global log_stats: event(rec: Info);
}

global bytes_received_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="net-received-bytes",
    $unit="",
    $help_text="Total number of bytes received",
]);

global packets_received_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="net-received-packets",
    $unit="",
    $help_text="Total number of packets received",
]);

global packets_dropped_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="net-dropped-packets",
    $unit="",
    $help_text="Total number of packets dropped",
]);

global link_packets_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="net-link-packets",
    $unit="",
    $help_text="Total number of packets on the packet source link before filtering",
]);

global packets_filtered_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="net-filtered-packets",
    $unit="",
    $help_text="Total number of packets filtered",
]);

global packet_lag_gf = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="net-packet-lag",
    $unit="seconds",
    $help_text="Difference of network time and wallclock time in seconds.",
]);

global no_labels: vector of string;

hook Telemetry::sync() {
	local net_stats = get_net_stats();
	Telemetry::counter_family_set(bytes_received_cf, no_labels, net_stats$bytes_recvd);
	Telemetry::counter_family_set(packets_received_cf, no_labels, net_stats$pkts_recvd);

	if ( reading_live_traffic() )
		{
		Telemetry::counter_family_set(packets_dropped_cf, no_labels, net_stats$pkts_dropped);
		Telemetry::counter_family_set(link_packets_cf, no_labels, net_stats$pkts_link);

		if ( net_stats?$pkts_filtered )
			Telemetry::counter_family_set(packets_filtered_cf, no_labels, net_stats$pkts_filtered);

		Telemetry::gauge_family_set(packet_lag_gf, no_labels,
		                            interval_to_double(current_time() - network_time()));
		}
}

event zeek_init() &priority=5
	{
	Log::create_stream(Stats::LOG, [$columns=Info, $ev=log_stats, $path="stats", $policy=log_policy]);
	}

event check_stats(then: time, last_ns: NetStats, last_cs: ConnStats, last_ps: ProcStats, last_es: EventStats, last_rs: ReassemblerStats, last_ts: TimerStats, last_fs: FileAnalysisStats, last_ds: DNSStats)
	{
	local nettime = network_time();
	local ns = get_net_stats();
	local cs = get_conn_stats();
	local ps = get_proc_stats();
	local es = get_event_stats();
	local rs = get_reassembler_stats();
	local ts = get_timer_stats();
	local fs = get_file_analysis_stats();
	local ds = get_dns_stats();

	local info: Info = [$ts=nettime,
			    $peer=peer_description,
			    $mem=ps$mem/1048576,
			    $pkts_proc=ns$pkts_recvd - last_ns$pkts_recvd,
			    $bytes_recv = ns$bytes_recvd  - last_ns$bytes_recvd,

			    $active_tcp_conns=cs$num_tcp_conns,
			    $tcp_conns=cs$cumulative_tcp_conns - last_cs$cumulative_tcp_conns,
			    $active_udp_conns=cs$num_udp_conns,
			    $udp_conns=cs$cumulative_udp_conns - last_cs$cumulative_udp_conns,
			    $active_icmp_conns=cs$num_icmp_conns,
			    $icmp_conns=cs$cumulative_icmp_conns - last_cs$cumulative_icmp_conns,

			    $reassem_tcp_size=rs$tcp_size,
			    $reassem_file_size=rs$file_size,
			    $reassem_frag_size=rs$frag_size,
			    $reassem_unknown_size=rs$unknown_size,

			    $events_proc=es$dispatched - last_es$dispatched,
			    $events_queued=es$queued - last_es$queued,

			    $timers=ts$cumulative - last_ts$cumulative,
			    $active_timers=ts$current,

			    $files=fs$cumulative - last_fs$cumulative,
			    $active_files=fs$current,

			    $dns_requests=ds$requests - last_ds$requests,
			    $active_dns_requests=ds$pending
			    ];

	# Someone's going to have to explain what this is and add a field to the Info record.
	# info$util = 100.0*((ps$user_time + ps$system_time) - (last_ps$user_time + last_ps$system_time))/(now-then);

	if ( reading_live_traffic() )
		{
		info$pkt_lag = current_time() - nettime;
		info$pkts_dropped = ns$pkts_dropped  - last_ns$pkts_dropped;
		info$pkts_link = ns$pkts_link  - last_ns$pkts_link;

		# This makes the assumption that if pkts_filtered is valid, it's been valid in
		# all of the previous calls.
		if ( ns?$pkts_filtered )
			info$pkts_filtered = ns$pkts_filtered - last_ns$pkts_filtered;
		}

	Log::write(Stats::LOG, info);

	if ( zeek_is_terminating() )
		# No more stats will be written or scheduled when Zeek is
		# shutting down.
		return;

	schedule report_interval { check_stats(nettime, ns, cs, ps, es, rs, ts, fs, ds) };
	}

event zeek_init()
	{
	schedule report_interval { check_stats(network_time(), get_net_stats(), get_conn_stats(), get_proc_stats(), get_event_stats(), get_reassembler_stats(), get_timer_stats(), get_file_analysis_stats(), get_dns_stats()) };
	}
