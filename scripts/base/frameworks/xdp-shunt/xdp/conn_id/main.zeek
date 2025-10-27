module XDP::ShuntConnID;

export {
	## Retrieves the current values in the canonical ID map. The parameters are
	## extra filtering before converting into script values. If both are provided,
	## they must both match to include the shunted connection.
	##
	## only_fin: True if filtering for packets with a fin/rst
	##
	## time_since_last_packet: Interval that must elapse since the last packet
	## to include
	##
	## Returns: A table of the "canonical" connection IDs getting shunted
	global get_map: function(xdp_prog: opaque of XDP::Program, only_fin: bool
	    &default=T, time_since_last_packet: interval &default=0sec)
	    : XDP::shunt_table;

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

function get_map(xdp_prog: opaque of XDP::Program, only_fin: bool &default=T,
    time_since_last_packet: interval &default=0sec): XDP::shunt_table
	{
	return _get_map(xdp_prog, only_fin, time_since_last_packet);
	}

function shunt(xdp_prog: opaque of XDP::Program, cid: conn_id): bool
	{
	return _shunt(xdp_prog, cid);
	}

function shunt_stats(xdp_prog: opaque of XDP::Program, cid: conn_id)
    : XDP::ShuntedStats
	{
	return _shunt_stats(xdp_prog, cid);
	}

function unshunt(xdp_prog: opaque of XDP::Program, cid: conn_id)
    : XDP::ShuntedStats
	{
	return _unshunt(xdp_prog, cid);
	}
