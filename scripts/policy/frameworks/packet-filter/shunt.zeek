@load base/frameworks/notice
@load base/frameworks/packet-filter

module PacketFilter;

export {
	## The maximum number of BPF based shunts that Zeek is allowed to perform.
	const max_bpf_shunts = 100 &redef;

	## Call this function to use BPF to shunt a connection (to prevent the
	## data packets from reaching Zeek).  For TCP connections, control
	## packets are still allowed through so that Zeek can continue logging
	## the connection and it can stop shunting once the connection ends.
	global shunt_conn: function(id: conn_id): bool;

	## This function will use a BPF expression to shunt traffic between
	## the two hosts given in the `conn_id` so that the traffic is never
	## exposed to Zeek's traffic processing.
	global shunt_host_pair: function(id: conn_id): bool;

	## Remove shunting for a host pair given as a `conn_id`.  The filter
	## is not immediately removed.  It waits for the occasional filter
	## update done by the `PacketFilter` framework.
	global unshunt_host_pair: function(id: conn_id): bool;

	## Performs the same function as the :zeek:id:`PacketFilter::unshunt_host_pair`
	## function, but it forces an immediate filter update.
	global force_unshunt_host_pair: function(id: conn_id): bool;

	## Retrieve the currently shunted connections.
	global current_shunted_conns: function(): set[conn_id];

	## Retrieve the currently shunted host pairs.
	global current_shunted_host_pairs: function(): set[conn_id];

	redef enum Notice::Type += {
		## Indicative that :zeek:id:`PacketFilter::max_bpf_shunts`
		## connections are already being shunted with BPF filters and
		## no more are allowed.
		No_More_Conn_Shunts_Available,

		## Limitations in BPF make shunting some connections with BPF
		## impossible.  This notice encompasses those various cases.
		Cannot_BPF_Shunt_Conn,
	};
}

global shunted_conns: set[conn_id];
global shunted_host_pairs: set[conn_id];

function shunt_filters()
	{
	# NOTE: this could wrongly match if a connection happens with the ports reversed.
	local tcp_filter = "";
	local udp_filter = "";
	for ( id in shunted_conns )
		{
		local prot = get_port_transport_proto(id$resp_p);

		local filt = fmt("host %s and port %d and host %s and port %d", id$orig_h, id$orig_p, id$resp_h, id$resp_p);
		if ( prot == udp )
			udp_filter = combine_filters(udp_filter, "and", filt);
		else if ( prot == tcp )
			tcp_filter = combine_filters(tcp_filter, "and", filt);
		}
	if ( tcp_filter != "" )
		tcp_filter = combine_filters("tcp and tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) == 0", "and", tcp_filter);
	local conn_shunt_filter = combine_filters(tcp_filter, "and", udp_filter);

	local hp_shunt_filter = "";
	for ( id in shunted_host_pairs )
		hp_shunt_filter = combine_filters(hp_shunt_filter, "and", fmt("host %s and host %s", id$orig_h, id$resp_h));

	local filter = combine_filters(conn_shunt_filter, "and", hp_shunt_filter);
	if ( filter != "" )
		PacketFilter::exclude("shunt_filters", filter);
}

event zeek_init() &priority=5
	{
	register_filter_plugin([
		$func()={ return shunt_filters(); }
		]);
	}

function current_shunted_conns(): set[conn_id]
	{
	return shunted_conns;
	}

function current_shunted_host_pairs(): set[conn_id]
	{
	return shunted_host_pairs;
	}

function reached_max_shunts(): bool
	{
	if ( |shunted_conns| + |shunted_host_pairs| > max_bpf_shunts )
		{
		NOTICE([$note=No_More_Conn_Shunts_Available,
		        $msg=fmt("%d BPF shunts are in place and no more will be added until space clears.", max_bpf_shunts)]);
		return T;
		}
	else
		return F;
	}

function shunt_host_pair(id: conn_id): bool
	{
	PacketFilter::filter_changed = T;

	if ( reached_max_shunts() )
		return F;

	add shunted_host_pairs[id];
	install();
	return T;
	}

function unshunt_host_pair(id: conn_id): bool
	{
	PacketFilter::filter_changed = T;

	if ( id in shunted_host_pairs )
		{
		delete shunted_host_pairs[id];
		return T;
		}
	else
		return F;
	}

function force_unshunt_host_pair(id: conn_id): bool
	{
	if ( unshunt_host_pair(id) )
		{
		install();
		return T;
		}
	else
		return F;
	}

function shunt_conn(id: conn_id): bool
	{
	if ( is_v6_addr(id$orig_h) )
		{
		NOTICE([$note=Cannot_BPF_Shunt_Conn,
		        $msg="IPv6 connections can't be shunted with BPF due to limitations in BPF",
		        $sub="ipv6_conn",
		        $id=id, $identifier=cat(id)]);
		return F;
		}

	if ( reached_max_shunts() )
		return F;

	PacketFilter::filter_changed = T;
	add shunted_conns[id];
	install();
	return T;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	# Don't rebuild the filter right away because the packet filter framework
	# will check every few minutes and update the filter if things have changed.
	if ( c$id in shunted_conns )
		delete shunted_conns[c$id];
	}
