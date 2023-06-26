##! This script adds link-layer address (MAC) information to the MySQL logs

@load base/protocols/mysql

module MySQL;

redef record Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the MySQL::Info structure.
event mysql_handshake(c: connection, username: string)
	{
	if ( c$orig?$l2_addr )
		c$mysql$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$mysql$resp_l2_addr = c$resp$l2_addr;
	}
