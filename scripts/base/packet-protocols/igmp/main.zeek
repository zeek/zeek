##! Implements base functionality for IGMP analysis.

module IGMP;

@load base/frameworks/logging

export {
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## A generic enum to map the v1/v2/v3 state changes to something common.
	type GroupAction: enum {
		JOIN = 0,
		LEAVE = 1,
	};

	## The record type which contains the column fields of the IGMP log.
	type Info: record {
		## The network time when the message was received.
		ts: time &log;
		## Source IP address of the message.
		src:  addr &log;
		## Destination group address, as per the
		## `IANA Multicast Address Registry <https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml>`_
		group:  addr &log;
		## IGMP action requested in the message.
		action:  GroupAction &log;
	};

	## Event that can be handled to access the IGMP record as it is sent on
	## to the logging framework.
	global log_igmp: event(rec: Info);

	## The number of repeats of the same action that are allowed before Zeek
	## suppresses such messages.
	const rate_limit_repeats = 10 &redef;

	## The amount of time for which repeat messages remain suppressed once
	## rate-limiting applies.
	const rate_limit_duration = 5min &redef;
}

## A record to keep track of the last state action seen for a specific src/group address
## pair. Stored in the active_states map.
type State: record {
	last_seen: time;
	repeats: count;
	last_action: GroupAction;
};

## The currently active igmp actions. This is used to manage rate-limiting.
global active_states: table[addr, addr] of State &create_expire=rate_limit_duration;

function should_log(src: addr, group: addr, action: GroupAction) : bool {
	local do_log: bool = F;

	if ( [ src, group ] in active_states ) {
		local state: State = active_states[src, group];

		state$repeats += 1;

		if ( state$last_action != action ) {
			state$last_action = action;
			state$repeats = 0;
			do_log = T;
		}
		else if ( state$repeats > rate_limit_repeats ) {
			state$repeats = 0;
			do_log = T;
		}
		else if ( network_time() - state$last_seen > rate_limit_duration ) {
			state$repeats = 0;
			do_log = T;
		}

		state$last_seen = network_time();
		active_states[src, group] = state;
	}
	else {
		do_log = T;

		local new_state: State = [$last_seen = network_time(), $repeats = 0, $last_action = action];
		active_states[src, group] = new_state;
	}

	return do_log;
}

event zeek_init() &priority=5
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 0x02, "IGMP") )
		{
		Reporter::error("Failed to register IGMP Spicy analyzer.");
		}

	Log::create_stream(IGMP::LOG, [$columns=Info, $ev=log_igmp, $path="igmp", $policy=log_policy]);
	}

event IGMP::membership_report_v1(source: addr, group_addr: addr) {
	if ( should_log(source, group_addr, JOIN) ) {
		Log::write(IGMP::LOG, Info(
			$ts = network_time(),
			$src = source,
			$group = group_addr,
			$action = JOIN));
	}
}

event IGMP::membership_report_v2(source: addr, group_addr: addr) {
	if ( should_log(source, group_addr, JOIN) ) {
		Log::write(IGMP::LOG, Info(
			$ts = network_time(),
			$src = source,
			$group = group_addr,
			$action = JOIN));
	}
}

event IGMP::membership_report_v3(source: addr, groups: vector of IGMP::Group) {
	for ( _, g in groups ) {
		local action: GroupAction;
		if ( g$group_type == IGMP::CHANGE_TO_EXCLUDE_MODE )
			action = JOIN;
		else if ( g$group_type == IGMP::CHANGE_TO_INCLUDE_MODE )
			action = LEAVE;
		else
			# TODO: Do the other types matter in terms of hosts
			# joining/leaving groups? They appear to mostly be informational
			# about existing states.
			return;

		if ( g$num_sources == 0 ) {
			if ( should_log(source, g$multicast_addr, action) ) {
				Log::write(IGMP::LOG, Info(
					$ts = network_time(),
					$src = source,
					$group = g$multicast_addr,
					$action = action));
			}
		}
		else {
			for ( _, s in g$sources ) {
				if ( should_log(s, g$multicast_addr, action) ) {
					Log::write(IGMP::LOG, Info(
						$ts = network_time(),
						$src = s,
						$group = g$multicast_addr,
						$action = action));
				}
			}
		}
	}
}

event IGMP::leave_group(source: addr, group_addr: addr) {
	if ( should_log(source, group_addr, LEAVE) ) {
		Log::write(IGMP::LOG, Info(
			$ts = network_time(),
			$src = source,
			$group = group_addr,
			$action = LEAVE));
	}
}
