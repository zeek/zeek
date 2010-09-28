@load app-summary

redef capture_filters += {
	["netbios-dgm"] = "udp port 138",
	["netbios-ssn"] = "tcp port 139",
	["microsft-ds"] = "tcp port 445",
};

module SMB_summary;

global smb_log = open_log_file("smb-summary") &redef;
global chris_log = open_log_file("chris-summary") &redef;

#const smb_transaction_func = {
#	["SMB_COM_TRANSACTION", 0x0 ] = "\\PIPE\\LANMAN\\",
#	["SMB_COM_TRANSACTION", 0x1 ] = "\\MAILSLOT\\",
#	["SMB_COM_TRANSACTION", 0x54] = "CallNamedPipe",
#	["SMB_COM_TRANSACTION", 0x53] = "WaitNamedPipe",
#	["SMB_COM_TRANSACTION", 0x26] = "TransactNmPipe",
#
#	["SMB_COM_TRANSACTION2", 0x0] = "TRANS2_OPEN2",
#	["SMB_COM_TRANSACTION2", 0x1] = "TRANS2_FIND_FIRST2",
#	["SMB_COM_TRANSACTION2", 0x2] = "TRANS2_FIND_NEXT2",
#	["SMB_COM_TRANSACTION2", 0x3] = "TRANS2_QUERY_FS_INFORMATION",
#	["SMB_COM_TRANSACTION2", 0x5] = "TRANS2_QUERY_PATH_INFORMATION",
#	["SMB_COM_TRANSACTION2", 0x6] = "TRANS2_SET_PATH_INFORMATION",
#	["SMB_COM_TRANSACTION2", 0x7] = "TRANS2_QUERY_FILE_INFORMATION",
#	["SMB_COM_TRANSACTION2", 0x8] = "TRANS2_SET_FILE_INFORMATION",
#	["SMB_COM_TRANSACTION2", 0x0d] = "TRANS2_CREATE_DIRECTORY",
#	["SMB_COM_TRANSACTION2", 0x0e] = "TRANS2_SESSION_SETUP",
#	["SMB_COM_TRANSACTION2", 0x10] = "TRANS2_GET_DFS_REFERRAL",
#} &default = function(cmd: string, subcmd: count): string
#	{
#	return fmt("%s/%d", cmd, subcmd);
#	};

type smb_req_resp: record {
	connection_id: conn_id;
	conn_start: time;
	func: string;
	cmd: string;
	start: time;
	num_req: count;
	req_size: count;
	num_resp: count;
	resp_size: count;
};

type smb_req_reply_group: record {
	trans: table[count] of smb_req_resp;
	first_req: count;
	last_req: count;
};

global smb_trans_table: table[conn_id] of smb_req_reply_group;

function lookup_smb_req_reply_group(id: conn_id, create: bool): smb_req_reply_group
	{
	if ( id !in smb_trans_table )
		{
		if ( create )
			{
			local trans: table[count] of smb_req_resp;
			smb_trans_table[id] = [
				$trans = trans, $first_req = 1, $last_req = 0];
			}
		else
			print fmt("SMB req_reply_group not found: %s",
				conn_id_string(id));
		}

	return smb_trans_table[id];
	}

function new_smb_req_resp(c: connection, cmd: string): smb_req_resp
	{
	local id = c$id;
	local g = lookup_smb_req_reply_group(id, T);

	if( is_udp_port(id$orig_p) || is_udp_port(id$resp_p) )
		print fmt("%.6f %s a new req_resp was triggered on a UDP connection!: %s",
			network_time(), conn_id_string(id), cmd);

	local t = [
		$connection_id = id, $conn_start = c$start_time,
		$cmd = cmd, $func = cmd,
		$start = network_time(),
		$num_req = 0, $req_size = 0,
		$num_resp = 0, $resp_size = 0
		];

	++g$last_req;
	g$trans[g$last_req] = t;

	return g$trans[g$last_req];
	}

function end_smb_req_resp(t: smb_req_resp)
	{
	print_app_summary(smb_log, t$connection_id, t$conn_start,
		t$func, t$start,
		t$num_req, t$req_size,
		t$num_resp, t$resp_size,
		fmt("cmd %s", t$cmd));
	}

function lookup_smb_req_resp(c: connection, is_orig: bool, cmd: string): smb_req_resp
	{
	local id = c$id;
	local g = lookup_smb_req_reply_group(id, T);

	if( is_udp_port(id$orig_p) || is_udp_port(id$resp_p) )
		print fmt("%.6f %s a lookup was triggered on a UDP connection!: %s",
			network_time(), conn_id_string(id), cmd);

	if ( g$first_req > g$last_req )
		{
		print fmt("%.6f %s request missing: %s",
			network_time(), conn_id_string(id), cmd);
		return new_smb_req_resp(c, cmd);
		}

	if ( is_orig )
		{
		return g$trans[g$last_req];
		}
	else if ( cmd == "(current)" )
		{
		return g$trans[g$first_req];
		}
	else
		{
		local t = g$trans[g$first_req];
		if ( g$first_req < g$last_req )
			{
			end_smb_req_resp(t);
			++g$first_req;
			t = g$trans[g$first_req];
			}
		if ( t$cmd != cmd )
			{
			if ( g$first_req < g$last_req )
				return lookup_smb_req_resp(c, is_orig, cmd);
			print fmt("%.6f %s SMB command-reply mismatch",
				network_time(), conn_id_string(id));
			}
		return t;
		}
	}

event smb_message(c: connection, hdr: smb_hdr, is_orig: bool, cmd:
						string, body_length: count, body : string)
	{
	print chris_log, fmt("%.6f %s %s", network_time(), conn_id_string(c$id), cmd);

	local t: smb_req_resp;

	if ( is_udp_port( c$id$orig_p ) || is_udp_port ( c$id$resp_p ) )
		{
		# dont need to keep track of UDP smb commands
		print_app_summary(smb_log, c$id, network_time(),
			cmd, network_time(),
			0, 0, 0, 0,
			fmt("cmd %s", cmd));
		}
	else if ( is_orig )
		{
		t = new_smb_req_resp(c, cmd);
		++t$num_req;
		t$req_size = t$req_size + body_length;
		}
	else
		{
		t = lookup_smb_req_resp(c, is_orig, cmd);
		++t$num_resp;
		t$resp_size = t$resp_size + body_length;
		}
	}

event smb_error(c: connection, hdr: smb_hdr,  cmd: count, cmd_str: string, data: string)
	{
	print chris_log, fmt("%.6f %s SMB_ERROR:%s", network_time(), conn_id_string(c$id), cmd_str);
	}

event dce_rpc_bind(c: connection, uuid: string)
	{
	local id = c$id;
	if ( id !in smb_trans_table )
		return;
	local t = lookup_smb_req_resp(c, T, "(current)");
	t$func = "DCE_RPC_BIND";
	}

event dce_rpc_request(c: connection, opnum: count, stub: string)
	{
	local id = c$id;
	if ( id !in smb_trans_table )
		return;
	local t = lookup_smb_req_resp(c, T, "(current)");
	t$func = "DCE_RPC_CALL";
	}

event dce_rpc_response(c: connection, opnum: count, stub: string)
	{
	local id = c$id;
	if ( id !in smb_trans_table )
		return;
	local t = lookup_smb_req_resp(c, F, "(current)");
	t$func = "DCE_RPC_CALL";
	}

event smb_com_transaction(c: connection, hdr: smb_hdr, trans: smb_trans, data: smb_trans_data, is_orig: bool)
	{
	if ( is_orig && !is_udp_port( c$id$orig_p ) )
		{
		local t = lookup_smb_req_resp(c, T, "(current)");
		}
	}

event smb_com_transaction2(c: connection, hdr: smb_hdr, trans: smb_trans, data: smb_trans_data, is_orig: bool)
	{
	if ( is_orig && !is_udp_port( c$id$orig_p ) )
		{
		local t = lookup_smb_req_resp(c, T, "(current)");
		}
	}

function end_smb_req_reply_group(g: smb_req_reply_group, index: count)
	{
	if ( index > g$last_req )
		return;

	if ( index >= g$first_req && index in g$trans )
		end_smb_req_resp(g$trans[index]);

	if( index in g$trans )
		{
		delete g$trans[index];
		end_smb_req_reply_group(g, index + 1);
		}
	}

event connection_state_remove(c: connection)
	{
	local id = c$id;
	if ( !is_udp_port( id$orig_p ) && id in smb_trans_table )
		{
		local g = smb_trans_table[id];
		end_smb_req_reply_group(g, 1);
		}
	}
