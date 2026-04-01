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
	global shunt: function(c: connection): bool;

	## Provides the shunting statistics for this connection ID.
	##
	## Returns: The shunting statistics
	##
	## .. zeek:see:: shunt unshunt
	global shunt_stats: function(c: connection): XDP::ShuntedStats;

	## Stops shunting anything with the conn_id.
	##
	## Returns: The shunted statistics right before removing
	##
	## .. zeek:see:: shunt shunt_stats
	global unshunt: function(c: connection): XDP::ShuntedStats;

	## If we should override Zeek's timeout, so it will only timeout a
	## connection if it has been shunted_inactivity_timeout time since the last shunted
	## packet, if shunted. Does not change anything if the connection was not
	## shunted.
	##
	## .. zeek:see:: shunted_inactivity_timeout shunted_connection_timeout
	option shunt_timeout: bool = T;

	## The interval to timeout after if a connection is shunted. Only applies
	## if shunt_timeout is enabled.
	##
	## .. zeek:see::shunt_timeout shunted_connection_timeout
	option shunted_inactivity_timeout: interval = 10sec;

	## The new timeout for the connection when it's shunted. Zeek will only
	## check if it's inactive each one of these intervals. Only applies if
	## shunt_timeout is enabled.
	##
	## .. zeek:see::shunt_timeout shunted_inactivity_timeout
	option shunted_connection_timeout: interval = 10sec;

	## If connections should always unshunt when the connection is removed
	## from Zeek.
	option unshunt_on_connection_remove: bool = T;

	global finalize_shunt: Conn::RemovalHook;
}

function get_map(time_since_last_packet: interval &default=0sec)
    : XDP::shunt_table
	{
	return _get_map(XDP::xdp_prog, time_since_last_packet);
	}

function shunt(c: connection): bool
	{
	local result = _shunt(XDP::xdp_prog, XDP::conn_id_to_canonical(c$id));
	if ( result )
		{
		if ( shunt_timeout )
			set_inactivity_timeout(c$id, shunted_connection_timeout);

		if ( unshunt_on_connection_remove )
			Conn::register_removal_hook(c, finalize_shunt);

		event shunted_conn(c$id);
		}

	return result;
	}

function shunt_stats(c: connection): XDP::ShuntedStats
	{
	return _shunt_stats(XDP::xdp_prog, XDP::conn_id_to_canonical(c$id));
	}

function unshunt(c: connection): XDP::ShuntedStats
	{
	local stats = _unshunt(XDP::xdp_prog, XDP::conn_id_to_canonical(c$id));
	if ( stats$present )
		event unshunted_conn(c$id, stats);

	return stats;
	}

hook ::connection_timing_out(c: connection)
	{
	if ( ! shunt_timeout )
		return;

	local stats = XDP::Shunt::ConnID::shunt_stats(c);

	# Early abort for connections that aren't shunted.
	if ( ! stats?$present )
		return;

	if ( stats?$timestamp
	    && network_time() - stats$timestamp < shunted_inactivity_timeout )
		break;
	}

hook finalize_shunt(c: connection)
	{
	XDP::Shunt::ConnID::unshunt(c);
	}
