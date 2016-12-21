##! This script adds VLAN information to the connection log.

@load base/protocols/conn

module Conn;

redef record Info += {
	## The outer VLAN for this connection, if applicable.
	vlan: int      &log &optional;

	## The inner VLAN for this connection, if applicable.
	inner_vlan: int      &log &optional;
};

# Add the VLAN information to the Conn::Info structure after the connection
# has been removed. This ensures it's only done once, and is done before the
# connection information is written to the log.
event connection_state_remove(c: connection)
	{
	if ( c?$vlan )
		c$conn$vlan = c$vlan;

	if ( c?$inner_vlan )
		c$conn$inner_vlan = c$inner_vlan;
	}

