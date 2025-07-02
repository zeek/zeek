##! This script adds PPPoE session ID information to the connection log.

@load base/protocols/conn

module Conn;

redef record Info += {
	## The PPPoE session id, if applicable for this connection.
	pppoe_session_id: int      &log &optional;
};

# Add the PPPoE session ID to the Conn::Info structure after the connection
# has been removed. This ensures it's only done once, and is done before the
# connection information is written to the log.
event connection_state_remove(c: connection)
	{
	if ( c?$pppoe_session_id )
		c$conn$pppoe_session_id = c$pppoe_session_id;
	}

