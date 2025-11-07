module XDP::Shunt::ConnID;

export {
	## Event raised whenever a connection is shunted.
	global shunted_conn: event(cid: conn_id);

	## Event raised whenever a connection is unshunted.
	global unshunted_conn: event(cid: conn_id, stats: XDP::ShuntedStats);

	## Retrieves the current values in the canonical ID map.
	##
	## time_since_last_packet: Interval that must elapse since the last packet
	## to include
	##
	## Returns: A table of the "canonical" connection IDs getting shunted
	global get_map: function(xdp_prog: opaque of XDP::Program,
	    time_since_last_packet: interval &default=0sec): XDP::shunt_table;

	## Starts shunting anything with the conn_id. This is bidirectional.
	##
	## Returns: Whether the operation succeeded
	##
	## .. zeek:see:: unshunt shunt_stats
	global shunt: function(xdp_prog: opaque of XDP::Program, cid: conn_id): bool;

	## Provides the shunting statistics for this connection ID.
	##
	## Returns: The shunting statistics
	##
	## .. zeek:see:: shunt unshunt
	global shunt_stats: function(xdp_prog: opaque of XDP::Program, cid: conn_id)
	    : XDP::ShuntedStats;

	## Stops shunting anything with the conn_id.
	##
	## Returns: The shunted statistics right before removing
	##
	## .. zeek:see:: shunt shunt_stats
	global unshunt: function(xdp_prog: opaque of XDP::Program, cid: conn_id)
	    : XDP::ShuntedStats;
}

function get_map(xdp_prog: opaque of XDP::Program,
    time_since_last_packet: interval &default=0sec): XDP::shunt_table
	{
	return _get_map(xdp_prog, time_since_last_packet);
	}

function shunt(xdp_prog: opaque of XDP::Program, cid: conn_id): bool
	{
	local result = _shunt(xdp_prog, cid);
	if ( result )
		event shunted_conn(cid);

	return result;
	}

function shunt_stats(xdp_prog: opaque of XDP::Program, cid: conn_id)
    : XDP::ShuntedStats
	{
	return _shunt_stats(xdp_prog, cid);
	}

function unshunt(xdp_prog: opaque of XDP::Program, cid: conn_id)
    : XDP::ShuntedStats
	{
	local stats = _unshunt(xdp_prog, cid);
	if ( stats$present )
		event unshunted_conn(cid, stats);

	return stats;
	}
