##! This script adds link-layer address (MAC) information to the dns logs

@load base/protocols/dns

module DNS;

redef record Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the DNS::Info structure.
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	if ( c$orig?$l2_addr )
		c$dns$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$dns$resp_l2_addr = c$resp$l2_addr;
	}
