##! This script adds link-layer address (MAC) information to the ntlm logs

@load base/protocols/ntlm
@load base/protocols/smb

module NTLM;

redef record Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the NTLM::Info structure.
event ntlm_negotiate(c: connection, request: NTLM::Negotiate)
	{
	if ( c$orig?$l2_addr )
		c$ntlm$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$ntlm$resp_l2_addr = c$resp$l2_addr;
	}
