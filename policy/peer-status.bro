# $Id: peer-status.bro 5954 2008-07-15 00:07:50Z vern $
#
# Emits process status "update" event periodically.

module PeerStatus;

export {
	type peer_status: record {
		res: bro_resources;
		stats: net_stats;
		current_time: time;
		cpu: double;		# average CPU load since last update
		default_filter: string;	# default capture filter
	};

	# Event sent periodically.
	global update: event(status: peer_status);

	# Update interval.
	const update_interval = 1 min;

	# This keeps track of all (local and remote) updates
	# (indexed by peer ID).
	global peers: table[peer_id] of peer_status;
}

global start_time = 0;
global cpu_last_proc_time = 0 secs;
global cpu_last_wall_time: time = 0;
global stats: net_stats;
global default_filter : string;

event net_stats_update(t: time, ns: net_stats)
	{
	stats = ns;
	}

event emit_update()
	{
	# Get CPU load.
	local res = resource_usage();
	local proc_time = res$user_time + res$system_time;
	local wall_time = current_time();
	local dproc = proc_time - cpu_last_proc_time;
	local dwall = wall_time - cpu_last_wall_time;
	local load = dproc / dwall * 100.0;
	cpu_last_proc_time = proc_time;
	cpu_last_wall_time = wall_time;

	local status: peer_status;
	status$res = res;
	status$stats = stats;
	status$current_time = current_time();
	status$cpu = load;
	status$default_filter = default_filter;

	event PeerStatus::update(status);

	schedule update_interval { emit_update() };
	}

event bro_init()
	{
	default_filter = build_default_pcap_filter();

	local res = resource_usage();
	cpu_last_proc_time = res$user_time + res$system_time;
	cpu_last_wall_time = current_time();
	stats = [$pkts_recvd=0, $pkts_dropped=0, $pkts_link=0];

	schedule update_interval { emit_update() };
	}

event update(status: peer_status)
	{
	local peer = get_event_peer();
	peers[peer$id] = status;
	}

event remote_connection_closed(p: event_peer)
	{
	if ( p$id in peers )
		delete peers[p$id];
	}
