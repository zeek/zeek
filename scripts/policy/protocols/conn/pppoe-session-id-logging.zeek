##! This script adds PPPoE session ID information to the connection log.

@load base/protocols/conn

module Conn;

redef record Info += {
	## The PPPoE session id, if applicable for this connection.
	pppoe_session_id: count &log &optional;
};

# Add the PPPoE session ID to the Conn::Info structure. We have to do this right
# at the beginning, while we are handling a packet.
event new_connection(c: connection)
	{
	local session_id = PacketAnalyzer::PPPoE::session_id();

	# no session ID
	if ( session_id == 0xFFFFFFFF )
		return;

	# FIXME: remove when GH-4688 is merged
	set_conn(c, F);

	c$conn$pppoe_session_id = session_id;
	}

