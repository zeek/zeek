##! This script adds the new column ``service_violation`` to the connection log.
##! The column contains the list of protocols in a connection that raised protocol
##! violations causing the analyzer to be removed. Protocols are listed in order
##! that they were removed.

@load base/protocols/conn

module Conn;

redef record Conn::Info += {
	## List of protocols in a connection that raised protocol violations
	## causing the analyzer to be removed.
	## Protocols are listed in order that they were removed.
	service_violation: vector of string  &log &optional;
};

# Not using connection removal hook, as this has to run for every connection.
event connection_state_remove(c: connection) &priority=4
	{
	if ( c?$conn && |c$service_violation| > 0 )
		{
		c$conn$service_violation = {};
		local sv: string;
		for ( sv in c$service_violation)
			c$conn$service_violation += to_lower(sv);
		}
	}
