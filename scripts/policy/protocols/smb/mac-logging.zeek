##! This script adds link-layer address (MAC) information to the smb logs

@load base/protocols/smb

module SMB;

redef record FileInfo += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

redef record TreeInfo += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the SMB::FileInfo and SMB::TreeInfo structure.
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
	{
	if ( c$orig?$l2_addr )
		{
		c$smb_state$current_tree$orig_l2_addr = c$orig$l2_addr;
		c$smb_state$current_file$orig_l2_addr = c$orig$l2_addr;
		}

	if ( c$resp?$l2_addr )
		{
		c$smb_state$current_tree$resp_l2_addr = c$resp$l2_addr;
		c$smb_state$current_file$resp_l2_addr = c$resp$l2_addr;
		}
	}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool)
	{
	if ( c$orig?$l2_addr )
		{
		c$smb_state$current_tree$orig_l2_addr = c$orig$l2_addr;
		c$smb_state$current_file$orig_l2_addr = c$orig$l2_addr;
		}

	if ( c$resp?$l2_addr )
		{
		c$smb_state$current_tree$resp_l2_addr = c$resp$l2_addr;
		c$smb_state$current_file$resp_l2_addr = c$resp$l2_addr;
		}
	}
