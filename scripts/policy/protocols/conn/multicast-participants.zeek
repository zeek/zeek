# Logs hosts known to take part in multicast conversations based on IGMP data. This is not
# all multicast connections, but just the ones for which Zeek knows active recipients.

@load base/protocols/conn
@load base/packet-protocols/igmp/types

module Conn;

export {
	redef enum Log::ID += { MULTICAST_PARTICIPANTS_LOG };

	## A default logging policy hook for the stream.
	global log_policy_multicast: Log::PolicyHook;

	# The record type which contains the column fields of the multicast participants
	# log.
	type MulticastParticipantsInfo: record {
		## The timestamp of the connection.
		ts: time &log;
		## The UID string for the connection. This is the uid field from the
		## original connection record.
		cid: string &log;
		## The address of the host origintating the connection to the multicast
		## group address.
		orig_h: addr &log;
		## The multicast group address for the connection.
		group_addr: addr &log;
		## The port used in the multicast connection.
		group_p: port &log;
		## The set of multicast participants collected from IGMP for the group
		## address.
		participants: set[addr] &log;
	};

	## Event that can be handled to access the :zeek:type:`Conn::Info`
	## record as it is sent on to the logging framework.
	global log_multicast: event(rec: MulticastParticipantsInfo);

	## The maximum number of IGMP groups that Zeek will track. If this limit is hit a
	## ``igmp_max_groups_exceeded`` weird will be reported and new groups will be
	## dropped and not tracked in the list of connections. Set this to zero to disable
	## the limiting.
	const max_igmp_groups: count = 500 &redef;

	## The maximum number of IGMP sources Zeek will track per group. If this limit is
	## hit a ``igmp_max_sources_exceeded`` weird will be reported and new sources
	## for that group will be dropped and not tracked in the list of connections. Set
	## this to zero to disable the limiting.
	const max_igmp_sources_per_group: count = 500 &redef;
}

redef record connection += {
	multicast_srcs: set[addr] &optional;
};

# Map connections to multicast group address and port number, but separately.  Multiple
# ports can be used on the same multicast group address.
global multicast_conns: table[addr] of set[conn_id];

# Map multicast group addresses to the addresses of the members. Entries expire after
# 400 seconds based on RFC 3376.
# TODO: This feels like it should be in the main IGMP script instead of here.
global igmp_group_sources: table[addr] of set[addr];

event zeek_init() &priority=5
	{
	Log::create_stream(MULTICAST_PARTICIPANTS_LOG, Log::Stream(
	    $columns=MulticastParticipantsInfo, $ev=log_multicast,
	    $path="multicast_participants", $policy=log_policy_multicast));
	}

hook multicast_removal_hook(c: connection)
	{
	# Multicast addresses only show up in the resp fields.
	if ( c$id$resp_h in 224.0.0.0/4 )
		{
		if ( c?$multicast_srcs && |c$multicast_srcs| > 0 )
			Log::write(MULTICAST_PARTICIPANTS_LOG, MulticastParticipantsInfo(
			    $ts=c$start_time, $cid=c$uid, $orig_h=c$id$orig_h,
			    $group_addr=c$id$resp_h,
			    $group_p=c$id$resp_p,
			    $participants=c$multicast_srcs));

		delete multicast_conns[c$id$resp_h][c$id];
		if ( |multicast_conns[c$id$resp_h]| == 0 )
			delete multicast_conns[c$id$resp_h];
		}
	}

event new_connection(c: connection)
	{
	# Multicast addresses only show up in the resp fields. Note that this doesn't
	# support ipv6 multicast because IGMP doesn't.
	if ( c$id$resp_h in 224.0.0.0/4 )
		{
		if ( c$id$resp_h !in multicast_conns )
			multicast_conns[c$id$resp_h] = set() &create_expire=400sec;

		add multicast_conns[c$id$resp_h][c$id];

		if ( c$id$resp_h in igmp_group_sources )
			c$multicast_srcs = copy(igmp_group_sources[c$id$resp_h]);
		else
			c$multicast_srcs = set();

		Conn::register_removal_hook(c, multicast_removal_hook);
		}
	}

function add_igmp_source(source: addr, group: addr)
	{
	if ( group !in igmp_group_sources ) {
		# This happens here because otherwise new sources for existing groups
		# wouldn't get added since we already hit the limit on groups.
		if ( max_igmp_groups > 0 && |igmp_group_sources| >= max_igmp_groups ) {
			Reporter::net_weird("igmp_max_groups_exceeded");
			# TODO: add 'X' to history to match this weird.
			return;
		}

		igmp_group_sources[group] = set();
	}

	if ( max_igmp_sources_per_group > 0 && |igmp_group_sources[group]| >= max_igmp_sources_per_group ) {
		Reporter::net_weird("igmp_max_sources_exceeded", fmt("%s", group));
		# TODO: add 'X' to history to match this weird.
		return;
	}

	add igmp_group_sources[group][source];

	if ( group in multicast_conns )
		{
		for ( cid in multicast_conns[group] )
			{
			local c = lookup_connection(cid);
			if ( c?$multicast_srcs )
				add c$multicast_srcs[source];
			}
		}
	}

event IGMP::membership_report_v1(source: addr, group_addr: addr)
	{
	add_igmp_source(source, group_addr);
	}

event IGMP::membership_report_v2(source: addr, group_addr: addr)
	{
	add_igmp_source(source, group_addr);
	}

event IGMP::membership_report_v3(source: addr, groups: vector of IGMP::Group)
	{
	for ( _, g in groups )
		{
		if ( g$group_type == IGMP::ALLOW_NEW_SOURCES
		    || g$group_type == IGMP::MODE_IS_INCLUDE
		    || ( g$num_sources == 0 && ( g$group_type == IGMP::MODE_IS_EXCLUDE || g$group_type == IGMP::CHANGE_TO_EXCLUDE_MODE ) ) )
			{
			add_igmp_source(source, g$multicast_addr);
			}
		else if ( g$group_type == IGMP::CHANGE_TO_INCLUDE_MODE
		    && g$num_sources == 0
		    && g$multicast_addr in igmp_group_sources )
			{
			delete igmp_group_sources[g$multicast_addr][source];
			if ( |igmp_group_sources[g$multicast_addr]| == 0 )
				delete igmp_group_sources[g$multicast_addr];
			}
		}
	}

event IGMP::leave_group(source: addr, group_addr: addr)
	{
	if ( group_addr in igmp_group_sources )
		delete igmp_group_sources[group_addr][source];
	if ( |igmp_group_sources[group_addr]| == 0 )
		delete igmp_group_sources[group_addr];
	}
