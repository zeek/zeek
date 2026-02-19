module XDP::Shunt::ConnID;

export {
	## Retrieves the current values in the canonical ID map.
	##
	## time_since_last_packet: Interval that must elapse since the last packet
	## to include
	##
	## Returns: A table of the "canonical" connection IDs getting shunted
	global get_map: function(time_since_last_packet: interval &default=0sec)
	    : XDP::shunt_table;

	## Starts shunting anything with the conn_id. This is bidirectional.
	##
	## Returns: Whether the operation succeeded
	##
	## .. zeek:see:: unshunt shunt_stats
	global shunt: function(cid: XDP::canonical_id): bool;

	## Provides the shunting statistics for this connection ID.
	##
	## Returns: The shunting statistics
	##
	## .. zeek:see:: shunt unshunt
	global shunt_stats: function(cid: XDP::canonical_id): XDP::ShuntedStats;

	## Stops shunting anything with the conn_id.
	##
	## Returns: The shunted statistics right before removing
	##
	## .. zeek:see:: shunt shunt_stats
	global unshunt: function(cid: XDP::canonical_id): XDP::ShuntedStats;

	## If we should override Zeek's timeout, so it will only timeout a
	## connection if it has been timeout_interval time since the last shunted
	## packet, if shunted. Does not change anything if the connection was not
	## shunted.
	##
	## .. zeek:see:: timeout_interval
	option shunt_timeout: bool = T;

	## The interval to timeout after if a connection is shunted. Only applies
	## if shunt_timeout is enabled.
	##
	## .. zeek:see::shunt_timeout
	option timeout_interval: interval = 10sec;

	## If connections should always unshunt when the connection is removed
	## from Zeek.
	option unshunt_on_connection_remove: bool = T;
}

function get_map(time_since_last_packet: interval &default=0sec)
    : XDP::shunt_table
	{
	return _get_map(XDP::xdp_prog, time_since_last_packet);
	}

function shunt(cid: XDP::canonical_id): bool
	{
	local result = _shunt(XDP::xdp_prog, cid);
	if ( result )
		event shunted_conn(cid);

	return result;
	}

function shunt_stats(cid: XDP::canonical_id): XDP::ShuntedStats
	{
	return _shunt_stats(XDP::xdp_prog, cid);
	}

function unshunt(cid: XDP::canonical_id): XDP::ShuntedStats
	{
	local stats = _unshunt(XDP::xdp_prog, cid);
	if ( stats$present )
		event unshunted_conn(cid, stats);

	return stats;
	}

hook ::connection_timing_out(c: connection)
	{
	if ( ! shunt_timeout )
		return;

	local stats = XDP::Shunt::ConnID::shunt_stats(XDP::conn_id_to_canonical(c$id));
	if ( stats?$timestamp && network_time() - stats$timestamp < timeout_interval )
		break;
	}

event connection_state_remove(c: connection)
	{
	if ( unshunt_on_connection_remove )
		XDP::Shunt::ConnID::unshunt(XDP::conn_id_to_canonical(c$id));
	}
