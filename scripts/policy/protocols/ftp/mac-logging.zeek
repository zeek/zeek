##! This script adds link-layer address (MAC) information to the ftp logs

@load base/protocols/ftp

module FTP;

redef record Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the FTP::Info structure.
event ftp_request(c: connection, command: string, arg: string)
	{
	if ( c$orig?$l2_addr )
		c$ftp$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$ftp$resp_l2_addr = c$resp$l2_addr;
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	if ( c$orig?$l2_addr )
		c$ftp$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$ftp$resp_l2_addr = c$resp$l2_addr;
	}
