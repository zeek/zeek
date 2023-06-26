##! This script adds link-layer address (MAC) information to the ssh logs

@load base/protocols/ssh

module SSH;

redef record Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the SSH::Info structure.
event ssh_client_version(c: connection, version: string)
{
	if ( c$orig?$l2_addr )
		c$ssh$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$ssh$resp_l2_addr = c$resp$l2_addr;
	}
