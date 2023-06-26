##! This script adds link-layer address (MAC) information to the dce-rpc logs

@load base/protocols/dce-rpc
@load base/protocols/smb

module DCE_RPC;

redef record Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the DCE_RPC::Info structure.
event dce_rpc_bind(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count)
	{
	if ( c$orig?$l2_addr )
		c$dce_rpc$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$dce_rpc$resp_l2_addr = c$resp$l2_addr;
	}
