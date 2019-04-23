# @TEST-EXEC: zeek -b -r $TRACES/tcp/handshake-reorder.trace %INPUT >out
# @TEST-EXEC: btest-diff out

# This tests the Connection::FlipRoles code path (SYN/SYN-ACK reversal).

# The check of likely_server_ports is before Connection::FlipRoles, so
# need to make sure that isn't the mechanism used to flip src/dst stuff.
redef likely_server_ports = {};

global first_packet: bool = T;

event new_packet(c: connection, p: pkt_hdr)
	{
	if ( ! first_packet )
		return;

	first_packet = F;

	print "schedule_analyzer, current conn_id", c$id;
	# Anticipate roles getting flipped in next packet.
	Analyzer::schedule_analyzer(141.142.228.5, 192.150.187.43, 80/tcp,
	                            Analyzer::ANALYZER_HTTP, 2mins);
	}

event connection_state_remove(c: connection)
	{
	print "connection_state_remove", c$id;
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{
	print "http_request", version, method, original_URI;
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	print "http_reply", version, code, reason;
	}
