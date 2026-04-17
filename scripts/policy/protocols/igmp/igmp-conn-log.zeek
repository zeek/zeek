# Logs hosts known to take part in multicast conversations based on IGMP data.

@load base/protocols/conn
@load base/packet-protocols/igmp/types

module IGMP;

export {
	redef enum Log::ID += { IGMP_CONN_LOG };

	global log_policy_igmp_conn: Log::PolicyHook;

	type IGMPConnInfo: record {
		ts: time &log;
		cid: string &log;
		orig_h: addr &log;
		multicast_addr: addr &log;
		multicast_p: port &log;
		participants: set[addr] &log;
	};

	## Event that can be handled to access the :zeek:type:`Conn::Info`
	## record as it is sent on to the logging framework.
	global log_igmp_conn: event(rec: IGMPConnInfo);
}

redef record connection += {
	igmp_srcs: set[addr] &optional;
};

# Map connections to multicast group address and port number, but separately.
# Multiple ports can be used on the same multicast group address.
global igmp_conns: table[addr] of set[conn_id];

# Map multicast group addresses to the addresses of the members.
# TODO: This feels like it should be in the main IGMP script instead of here.
global igmp_sources: table[addr] of set[addr];

event zeek_init() &priority=5
	{
	Log::create_stream(IGMP::IGMP_CONN_LOG, Log::Stream($columns=IGMPConnInfo, $ev=log_igmp_conn,
	    $path="igmp_conn", $policy=log_policy_igmp_conn));
	}

hook multicast_removal_hook(c: connection)
	{
	# Multicast addresses only show up in the resp fields.
	if ( c$id$resp_h in 224.0.0.0/4 )
		{
		if ( c?$igmp_srcs && |c$igmp_srcs| > 0 )
			Log::write(IGMP::IGMP_CONN_LOG, IGMPConnInfo($ts=c$start_time, $cid=c$uid,
			    $orig_h=c$id$orig_h,
			    $multicast_addr=c$id$resp_h,
			    $multicast_p=c$id$resp_p,
			    $participants=c$igmp_srcs));

		delete igmp_conns[c$id$resp_h][c$id];
		}
	}

event new_connection(c: connection)
	{
	# Multicast addresses only show up in the resp fields. Note that this doesn't
	# support ipv6 multicast because IGMP doesn't.
	if ( c$id$resp_h in 224.0.0.0/4 )
		{
		if ( c$id$resp_h !in igmp_conns )
			igmp_conns[c$id$resp_h] = set();

		add igmp_conns[c$id$resp_h][c$id];

		if ( c$id$resp_h in igmp_sources )
			c$igmp_srcs = copy(igmp_sources[c$id$resp_h]);
		else
			c$igmp_srcs = set();

		Conn::register_removal_hook(c, multicast_removal_hook);
		}
	}

function add_igmp_source(source: addr, group: addr)
	{
	if ( group !in igmp_sources )
		igmp_sources[group] = set();

	add igmp_sources[group][source];

	if ( group in igmp_conns )
		{
		for ( cid in igmp_conns[group] )
			{
			local c = lookup_connection(cid);
			if ( c?$igmp_srcs )
				add c$igmp_srcs[source];
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
		    && g$multicast_addr in igmp_sources )
			{
			delete igmp_sources[g$multicast_addr][source];
			}
		}
	}

event IGMP::leave_group(source: addr, group_addr: addr)
	{
	delete igmp_sources[group_addr][source];
	}
