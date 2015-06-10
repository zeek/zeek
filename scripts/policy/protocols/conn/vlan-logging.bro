##! This script add VLAN information to the connection logs

@load base/protocols/conn

module Conn;

redef record Info += {
	## The Outer VLAN for this connection, if applicable
	outer_vlan: int      &log &optional;

	## The Inner VLAN for this connection, if applicable
	inner_vlan: int      &log &optional;
};

# Add the VLAN information to the Conn::Info structure after the connection has
# been removed. This ensures it's only done once, and is done before
# the connection information is written to the log.
event connection_state_remove(c: connection) &priority=5
	{
	if (c?$outer_vlan)
		{
		c$conn$outer_vlan = c$outer_vlan;
		}

	if (c?$inner_vlan)
		{
		c$conn$inner_vlan = c$inner_vlan;
		}
	}
