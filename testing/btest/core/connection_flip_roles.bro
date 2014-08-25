# @TEST-EXEC: bro -b -r $TRACES/tcp/handshake-reorder.trace %INPUT >out
# @TEST-EXEC: btest-diff out

# This tests the Connection::FlipRoles code path (SYN/SYN-ACK reversal).

# The check of likely_server_ports is before Connection::FlipRoles, so
# need to make sure that isn't the mechanism used to flip src/dst stuff.
redef likely_server_ports = {};

global first_packet: bool = T;

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
	{
	if ( ! first_packet )
		return;

	first_packet = F;
	print "first packet conn_id", c$id;
	}

event connection_state_remove(c: connection)
	{
	print "connection_state_remove", c$id;
	}
