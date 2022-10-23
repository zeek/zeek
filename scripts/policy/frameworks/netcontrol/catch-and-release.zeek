##! Implementation of catch-and-release functionality for NetControl.

@load base/frameworks/netcontrol
@load base/frameworks/cluster

module NetControl;

export {

	redef enum Log::ID += { CATCH_RELEASE };

	global log_policy_catch_release: Log::PolicyHook;

	## This record is used for storing information about current blocks that are
	## part of catch and release.
	type BlockInfo: record {
		## Absolute time indicating until when a block is inserted using NetControl.
		block_until: time &optional;
		## Absolute time indicating until when an IP address is watched to reblock it.
		watch_until: time;
		## Number of times an IP address was reblocked.
		num_reblocked: count &default=0;
		## Number indicating at which catch and release interval we currently are.
		current_interval: count;
		## ID of the inserted block, if any.
		current_block_id: string;
		## User specified string.
		location: string &optional;
	};

	## The enum that contains the different kinds of messages that are logged by
	## catch and release.
	type CatchReleaseActions: enum {
		## Log lines marked with info are purely informational; no action was taken.
		INFO,
		## A rule for the specified IP address already existed in NetControl (outside
		## of catch-and-release). Catch and release did not add a new rule, but is now
		## watching the IP address and will add a new rule after the current rule expires.
		ADDED,
		## A drop was requested by catch and release.
		DROP_REQUESTED,
		## An address was successfully blocked by catch and release.
		DROPPED,
		## An address was unblocked after the timeout expired.
		UNBLOCK,
		## An address was forgotten because it did not reappear within the `watch_until` interval.
		FORGOTTEN,
		## A watched IP address was seen again; catch and release will re-block it.
		SEEN_AGAIN
	};

	## The record type that is used for representing and logging
	type CatchReleaseInfo: record {
		## The absolute time indicating when the action for this log-line occurred.
		ts: time &log;
		## The rule id that this log line refers to.
		rule_id: string &log &optional;
		## The IP address that this line refers to.
		ip: addr &log;
		## The action that was taken in this log-line.
		action: CatchReleaseActions &log;
		## The current block_interval (for how long the address is blocked).
		block_interval: interval &log &optional;
		## The current watch_interval (for how long the address will be watched and re-block if it reappears).
		watch_interval: interval &log &optional;
		## The absolute time until which the address is blocked.
		blocked_until: time &log &optional;
		## The absolute time until which the address will be monitored.
		watched_until: time &log &optional;
		## Number of times that this address was blocked in the current cycle.
		num_blocked: count &log &optional;
		## The user specified location string.
		location: string &log &optional;
		## Additional informational string by the catch and release framework about this log-line.
		message: string &log &optional;
	};

	## Stops all packets involving an IP address from being forwarded. This function
	## uses catch-and-release functionality, where the IP address is only dropped for
	## a short amount of time that is incremented steadily when the IP is encountered
	## again.
	##
	## In cluster mode, this function works on workers as well as the manager. On managers,
	## the returned :zeek:see:`NetControl::BlockInfo` record will not contain the block ID,
	## which will be assigned on the manager.
	##
	## a: The address to be dropped.
	##
	## t: How long to drop it, with 0 being indefinitely.
	##
	## location: An optional string describing where the drop was triggered.
	##
	## Returns: The :zeek:see:`NetControl::BlockInfo` record containing information about
	##          the inserted block.
	global drop_address_catch_release: function(a: addr, location: string &default="") : BlockInfo;

	## Removes an address from being watched with catch and release. Returns true if the
	## address was found and removed; returns false if it was unknown to catch and release.
	##
	## If the address is currently blocked, and the block was inserted by catch and release,
	## the block is removed.
	##
	## a: The address to be unblocked.
	##
	## reason: A reason for the unblock.
	##
	## Returns: True if the address was unblocked.
	global unblock_address_catch_release: function(a: addr, reason: string &default="") : bool;

	## This function can be called to notify the catch and release script that activity by
	## an IP address was seen. If the respective IP address is currently monitored by catch and
	## release and not blocked, the block will be reinstated. See the documentation of watch_new_connection
	## which events the catch and release functionality usually monitors for activity.
	##
	## a: The address that was seen and should be re-dropped if it is being watched.
	global catch_release_seen: function(a: addr);

	## Get the :zeek:see:`NetControl::BlockInfo` record for an address currently blocked by catch and release.
	## If the address is unknown to catch and release, the watch_until time will be set to 0.
	##
	## In cluster mode, this function works on the manager and workers. On workers, the data will
	## lag slightly behind the manager; if you add a block, it will not be instantly available via
	## this function.
	##
	## a: The address to get information about.
	##
	## Returns: The :zeek:see:`NetControl::BlockInfo` record containing information about
	##          the inserted block.
	global get_catch_release_info: function(a: addr) : BlockInfo;

	## Event is raised when catch and release cases management of an IP address because no
	## activity was seen within the watch_until period.
	##
	## a: The address that is no longer being managed.
	##
	## bi: The :zeek:see:`NetControl::BlockInfo` record containing information about the block.
	global catch_release_forgotten: event(a: addr, bi: BlockInfo);

	## If true, catch_release_seen is called on the connection originator in new_connection,
	## connection_established, partial_connection, connection_attempt, connection_rejected,
	## connection_reset and connection_pending
	const watch_connections = T &redef;

	## If true, catch and release warns if packets of an IP address are still seen after it
	## should have been blocked.
	option catch_release_warn_blocked_ip_encountered = F;

	## Time intervals for which subsequent drops of the same IP take
	## effect.
	const catch_release_intervals: vector of interval = vector(10min, 1hr, 24hrs, 7days) &redef;

	## Event that can be handled to access the :zeek:type:`NetControl::CatchReleaseInfo`
	## record as it is sent on to the logging framework.
	global log_netcontrol_catch_release: event(rec: CatchReleaseInfo);

	# Cluster events for catch and release
	global catch_release_block_new: event(a: addr, b: BlockInfo);
	global catch_release_block_delete: event(a: addr);
	global catch_release_add: event(a: addr, location: string);
	global catch_release_delete: event(a: addr, reason: string);
	global catch_release_encountered: event(a: addr);
}

# Set that is used to only send seen notifications to the master every ~30 seconds.
global catch_release_recently_notified: set[addr] &create_expire=30secs;

event zeek_init() &priority=5
	{
	Log::create_stream(NetControl::CATCH_RELEASE, [$columns=CatchReleaseInfo, $ev=log_netcontrol_catch_release, $path="netcontrol_catch_release", $policy=log_policy_catch_release]);
	}

function get_watch_interval(current_interval: count): interval
	{
	if ( (current_interval + 1) in catch_release_intervals )
		return catch_release_intervals[current_interval+1];
	else
		return catch_release_intervals[current_interval];
	}

function populate_log_record(ip: addr, bi: BlockInfo, action: CatchReleaseActions): CatchReleaseInfo
	{
	local log = CatchReleaseInfo($ts=network_time(), $ip=ip, $action=action,
	        $block_interval=catch_release_intervals[bi$current_interval],
	        $watch_interval=get_watch_interval(bi$current_interval),
	        $watched_until=bi$watch_until,
	        $num_blocked=bi$num_reblocked+1
	        );

	if ( bi?$block_until )
		log$blocked_until = bi$block_until;

	if ( bi?$current_block_id && bi$current_block_id != "" )
		log$rule_id = bi$current_block_id;

	if ( bi?$location )
		log$location = bi$location;

	return log;
	}

function per_block_interval(t: table[addr] of BlockInfo, idx: addr): interval
	{
	local remaining_time = t[idx]$watch_until - network_time();
	if ( remaining_time < 0secs )
		remaining_time = 0secs;

@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )
	if ( remaining_time == 0secs )
		{
		local log = populate_log_record(idx, t[idx], FORGOTTEN);
		Log::write(CATCH_RELEASE, log);

		event NetControl::catch_release_forgotten(idx, t[idx]);
		}
@endif

	return remaining_time;
	}

# This is the internally maintained table containing all the addresses that are currently being
# watched to see if they will re-surface. After the time is reached, monitoring of that specific
# IP will stop.
global blocks: table[addr] of BlockInfo = {}
	&create_expire=0secs
	&expire_func=per_block_interval;


@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init()
	{
	Broker::auto_publish(Cluster::worker_topic, NetControl::catch_release_block_new);
	Broker::auto_publish(Cluster::worker_topic, NetControl::catch_release_block_delete);
	}
@else
event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, NetControl::catch_release_add);
	Broker::auto_publish(Cluster::manager_topic, NetControl::catch_release_delete);
	Broker::auto_publish(Cluster::manager_topic, NetControl::catch_release_encountered);
	}
@endif

@endif

function cr_check_rule(r: Rule): bool
	{
	if ( r$ty == DROP && r$entity$ty == ADDRESS )
		{
		local ip = r$entity$ip;
		if ( ( is_v4_subnet(ip) && subnet_width(ip) == 32 ) || ( is_v6_subnet(ip) && subnet_width(ip) == 128 ) )
			{
			if ( subnet_to_addr(ip) in blocks )
				return T;
			}
		}

		return F;
	}

@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )

event rule_added(r: Rule, p: PluginState, msg: string)
	{
	if ( !cr_check_rule(r) )
		return;

	local ip = subnet_to_addr(r$entity$ip);
	local bi = blocks[ip];

	local log = populate_log_record(ip, bi, DROPPED);
	if ( msg != "" )
		log$message = msg;
	Log::write(CATCH_RELEASE, log);
	}


event rule_timeout(r: Rule, i: FlowInfo, p: PluginState)
	{
	if ( !cr_check_rule(r) )
		return;

	local ip = subnet_to_addr(r$entity$ip);
	local bi = blocks[ip];

	local log = populate_log_record(ip, bi, UNBLOCK);
	if ( bi?$block_until )
		{
		local difference: interval = network_time() - bi$block_until;
		if ( interval_to_double(difference) > 60 || interval_to_double(difference) < -60 )
			log$message = fmt("Difference between network_time and block time excessive: %f", difference);
		}

	Log::write(CATCH_RELEASE, log);
	}

@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event catch_release_add(a: addr, location: string)
	{
	drop_address_catch_release(a, location);
	}

event catch_release_delete(a: addr, reason: string)
	{
	unblock_address_catch_release(a, reason);
	}

event catch_release_encountered(a: addr)
	{
	catch_release_seen(a);
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event catch_release_block_new(a: addr, b: BlockInfo)
	{
	blocks[a] = b;
	}

event catch_release_block_delete(a: addr)
	{
	if ( a in blocks )
		delete blocks[a];
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
@endif

function get_catch_release_info(a: addr): BlockInfo
	{
	if ( a in blocks )
		return blocks[a];

	return BlockInfo($watch_until=double_to_time(0), $current_interval=0, $current_block_id="");
	}

function drop_address_catch_release(a: addr, location: string &default=""): BlockInfo
	{
	local bi: BlockInfo;
	local log: CatchReleaseInfo;

	if ( a in blocks )
		{
		log = populate_log_record(a, blocks[a], INFO);
		log$message = "Already blocked using catch-and-release - ignoring duplicate";
		Log::write(CATCH_RELEASE, log);

		return blocks[a];
		}

	local e = Entity($ty=ADDRESS, $ip=addr_to_subnet(a));
	if ( [e,DROP] in rule_entities )
		{
		local r = rule_entities[e,DROP];

		bi = BlockInfo($watch_until=network_time()+catch_release_intervals[1], $current_interval=0, $current_block_id=r$id);
		if ( location != "" )
			bi$location = location;
@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )
		log = populate_log_record(a, bi, ADDED);
		log$message = "Address already blocked outside of catch-and-release. Catch and release will monitor and only actively block if it appears in network traffic.";
		Log::write(CATCH_RELEASE, log);
		blocks[a] = bi;
		event NetControl::catch_release_block_new(a, bi);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		event NetControl::catch_release_add(a, location);
@endif
		return bi;
		}

	local block_interval = catch_release_intervals[0];

@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled()  && Cluster::local_node_type() == Cluster::MANAGER ) )
	local ret = drop_address(a, block_interval, location);

	if ( ret != "" )
		{
		bi = BlockInfo($watch_until=network_time()+catch_release_intervals[1], $block_until=network_time()+block_interval, $current_interval=0, $current_block_id=ret);
		if ( location != "" )
			bi$location = location;
		blocks[a] = bi;
		event NetControl::catch_release_block_new(a, bi);
		blocks[a] = bi;
		log = populate_log_record(a, bi, DROP_REQUESTED);
		Log::write(CATCH_RELEASE, log);
		return bi;
		}
	Reporter::error(fmt("Catch and release could not add block for %s; failing.", a));
	return BlockInfo($watch_until=double_to_time(0), $current_interval=0, $current_block_id="");
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
	bi = BlockInfo($watch_until=network_time()+catch_release_intervals[1], $block_until=network_time()+block_interval, $current_interval=0, $current_block_id="");
	event NetControl::catch_release_add(a, location);
	return bi;
@endif

	}

function unblock_address_catch_release(a: addr, reason: string &default=""): bool
	{
	if ( a !in blocks )
		return F;

@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )
	local bi = blocks[a];
	local log = populate_log_record(a, bi, UNBLOCK);
	if ( reason != "" )
		log$message = reason;
	Log::write(CATCH_RELEASE, log);
	delete blocks[a];
	if ( bi?$block_until && bi$block_until > network_time() && bi$current_block_id != "" )
		remove_rule(bi$current_block_id, reason);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
	event NetControl::catch_release_block_delete(a);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
	event NetControl::catch_release_delete(a, reason);
@endif

	return T;
	}

function catch_release_seen(a: addr)
	{
	if ( a in blocks )
		{
@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )
		local bi = blocks[a];
		local log: CatchReleaseInfo;
		local e = Entity($ty=ADDRESS, $ip=addr_to_subnet(a));

		if ( [e,DROP] in rule_entities )
			{
			if ( catch_release_warn_blocked_ip_encountered == F )
				return;

			# This should be blocked - block has not been applied yet by hardware? Ignore for the moment...
			log = populate_log_record(a, bi, INFO);
			log$action = INFO;
			log$message = "Block seen while in rule_entities. No action taken.";
			Log::write(CATCH_RELEASE, log);
			return;
			}

		# ok, this one returned again while still in the backoff period.

		local try = bi$current_interval;
		if ( (try+1) in catch_release_intervals )
			++try;

		bi$current_interval = try;
		if ( (try+1) in catch_release_intervals )
			bi$watch_until = network_time() + catch_release_intervals[try+1];
		else
			bi$watch_until = network_time() + catch_release_intervals[try];

		bi$block_until = network_time() + catch_release_intervals[try];
		++bi$num_reblocked;

		local block_interval = catch_release_intervals[try];
		local location = "";
		if ( bi?$location )
			location = bi$location;
		local drop = drop_address(a, block_interval, fmt("Re-drop by catch-and-release: %s", location));
		bi$current_block_id = drop;

		blocks[a] = bi;

		log = populate_log_record(a, bi, SEEN_AGAIN);
		Log::write(CATCH_RELEASE, log);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
	event NetControl::catch_release_block_new(a, bi);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
	if ( a in catch_release_recently_notified )
		return;

	event NetControl::catch_release_encountered(a);
	add catch_release_recently_notified[a];
@endif

		return;
		}

	return;
	}

event new_connection(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_established(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event partial_connection(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_attempt(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_rejected(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_reset(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_pending(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}
