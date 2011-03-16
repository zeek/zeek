# $Id:$

redef rewriting_smb_trace = T;


event smb_message(c: connection, hdr: smb_hdr, is_orig: bool, cmd: string, body_length: count, body: string)
	{
	}

event smb_com_tree_connect_andx(c: connection, hdr: smb_hdr, path: string, service: string)
	{
	}

event smb_com_tree_disconnect(c: connection, hdr: smb_hdr)
	{
	}

event smb_com_nt_create_andx(c: connection, hdr: smb_hdr, name: string)
	{
	}

event smb_com_transaction(c: connection, hdr: smb_hdr, trans: smb_trans, data: smb_trans_data, is_orig: bool)
	{
	}

event smb_com_transaction2(c: connection, hdr: smb_hdr, trans: smb_trans, data: smb_trans_data, is_orig: bool)
	{
	}

event smb_com_trans_mailslot(c: connection, hdr: smb_hdr, trans: smb_trans, data: smb_trans_data, is_orig: bool)
	{
	}

event smb_com_trans_rap(c: connection, hdr: smb_hdr, trans: smb_trans, data: smb_trans_data, is_orig: bool)
	{
	}

event smb_com_trans_pipe(c: connection, hdr: smb_hdr, trans: smb_trans, data: smb_trans_data, is_orig: bool)
	{
	}

event smb_com_read_andx(c: connection, hdr: smb_hdr, data: string)
	{
	}

event smb_com_write_andx(c: connection, hdr: smb_hdr, data: string)
	{
	}

event smb_get_dfs_referral(c: connection, hdr: smb_hdr, max_referral_level: count, file_name: string)
	{
	}

event smb_com_negotiate(c: connection, hdr: smb_hdr)
	{
	}

event smb_com_negotiate_response(c: connection, hdr: smb_hdr, dialect_index: count)
	{
	}

event smb_com_setup_andx(c: connection, hdr: smb_hdr)
	{
	}

event smb_com_generic_andx(c: connection, hdr: smb_hdr)
	{
	}

event smb_com_close(c: connection, hdr: smb_hdr)
	{
	}

event smb_com_logoff_andx(c: connection, hdr: smb_hdr)
	{
	}

event smb_error(c: connection, hdr: smb_hdr, cmd: count, cmd_str: string, data: string)
	{
	}
