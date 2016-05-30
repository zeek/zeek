##! This script adds MAC address information to the connection logs.

@load base/protocols/conn

module Conn;

redef record Info += {
	## The Ethernet MAC source address for this connection, if applicable.
	eth_src: string &log &optional;

	## The Ethernet MAC destination address for this connection, if applicable.
	eth_dst: string &log &optional;
};

event connection_state_remove(c: connection)
	{
	if ( c?$eth_src )
		c$conn$eth_src = c$eth_src;
	
	if ( c?$eth_dst )
		c$conn$eth_dst = c$eth_dst;
	}

