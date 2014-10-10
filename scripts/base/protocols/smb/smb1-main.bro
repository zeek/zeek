module SMB1;

redef record SMB::CmdInfo += {
	## Dialects offered by the client	
	smb1_offered_dialects: string_vec &optional;
};

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=5
	{
	if ( ! c?$smb_state )
		{
		local state: SMB::State;
		state$fid_map = table();
		state$tid_map = table();
		state$uid_map = table();
		state$pipe_map = table();
		state$pending_cmds = table();
		c$smb_state = state;
		}

	local smb_state = c$smb_state;
	local tid = hdr$tid;
	local uid = hdr$uid;
	local pid = hdr$pid;
	local mid = hdr$mid;

	if ( uid in smb_state$uid_map )
		{
		smb_state$current_cmd$username = smb_state$uid_map[uid];
		}

	if ( tid !in smb_state$tid_map )
		{
		local tmp_tree: SMB::TreeInfo = [$uid=c$uid, $id=c$id];
		smb_state$tid_map[tid] = tmp_tree;
		}
	smb_state$current_tree = smb_state$tid_map[tid];
	if ( smb_state$current_tree?$path )
		{
		smb_state$current_cmd$tree = smb_state$current_tree$path;
		}
		
	if ( smb_state$current_tree?$service )
		{
		smb_state$current_cmd$tree_service = smb_state$current_tree$service;
		}
	
	if ( mid !in smb_state$pending_cmds )
		{
		local tmp_cmd: SMB::CmdInfo = [$ts=network_time(), $uid=c$uid, $id=c$id, $version="SMB1", $command = SMB1::commands[hdr$command]];

		local tmp_file: SMB::FileInfo = [$ts=network_time(), $uid=c$uid, $id=c$id];
		tmp_cmd$referenced_file = tmp_file;
		tmp_cmd$referenced_tree = smb_state$current_tree;
		
		smb_state$pending_cmds[mid] = tmp_cmd;
		}
	
	smb_state$current_cmd = smb_state$pending_cmds[mid];

	if ( !is_orig )
		{
		smb_state$current_cmd$rtt = network_time() - smb_state$current_cmd$ts;
		smb_state$current_cmd$status = SMB::statuses[hdr$status]$id;
		}
}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-5
	{
	# Is this a response?
	if ( !is_orig )
		{
		if ( ( c$smb_state$current_cmd$status !in SMB::ignored_command_statuses ) &&
		     ( c$smb_state$current_cmd$command !in SMB::deferred_logging_cmds ) )
			{
			Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
			}
		delete c$smb_state$pending_cmds[hdr$mid];
		}
	}


event smb1_transaction2_request(c: connection, hdr: SMB1::Header, sub_cmd: count)
	{
	c$smb_state$current_cmd$sub_command = SMB1::trans2_sub_commands[sub_cmd];
	}


event smb1_negotiate_request(c: connection, hdr: SMB1::Header, dialects: string_vec) &priority=5
	{
	c$smb_state$current_cmd$smb1_offered_dialects = dialects;
	}

event smb1_negotiate_response(c: connection, hdr: SMB1::Header, response: SMB1::NegotiateResponse) &priority=5
	{
	if ( c$smb_state$current_cmd?$smb1_offered_dialects )
		{
		if ( response?$ntlm )
			{
			c$smb_state$current_cmd$argument = c$smb_state$current_cmd$smb1_offered_dialects[response$ntlm$dialect_index];
			}

		delete c$smb_state$current_cmd$smb1_offered_dialects;
		}
	}
	
event smb1_negotiate_response(c: connection, hdr: SMB1::Header, response: SMB1::NegotiateResponse) &priority=-5
	{
	if ( c$smb_state$current_cmd$status !in SMB::ignored_command_statuses )
		{
		Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
		}
	}
	
event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) &priority=5
	{
	local tmp_tree: SMB::TreeInfo = [$ts=network_time(), $uid=c$uid, $id=c$id, $path=path, $service=service];

	c$smb_state$current_cmd$referenced_tree = tmp_tree;
	c$smb_state$current_cmd$argument = path;
	}

event smb1_tree_connect_andx_response(c: connection, hdr: SMB1::Header, service: string, native_file_system: string) &priority=5
	{
	c$smb_state$current_cmd$referenced_tree$service = service;
	c$smb_state$current_cmd$tree_service = service;
	
	c$smb_state$current_cmd$referenced_tree$native_file_system = native_file_system;

	c$smb_state$current_tree = c$smb_state$current_cmd$referenced_tree;
	c$smb_state$tid_map[hdr$tid] = c$smb_state$current_tree;
	}

event smb1_tree_connect_andx_response(c: connection, hdr: SMB1::Header, service: string, native_file_system: string) &priority=-5
	{
	Log::write(SMB::MAPPING_LOG, c$smb_state$current_tree);

	if ( c$smb_state$current_cmd$status !in SMB::ignored_command_statuses )
		{
		Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
		}
	}

event smb1_nt_create_andx_request(c: connection, hdr: SMB1::Header, name: string) &priority=5
	{
	local tmp_file: SMB::FileInfo = [$ts=network_time(), $uid=c$uid, $id=c$id];
	c$smb_state$current_cmd$referenced_file = tmp_file;
	c$smb_state$current_cmd$referenced_file$name = name;
	c$smb_state$current_cmd$referenced_file$action = SMB::FILE_OPEN;
	c$smb_state$current_file = c$smb_state$current_cmd$referenced_file;
	c$smb_state$current_cmd$argument = name;
	}

event smb1_nt_create_andx_response(c: connection, hdr: SMB1::Header, file_id: count, file_size: count, times: SMB::MACTimes) &priority=5
	{
	c$smb_state$current_cmd$referenced_file$action = SMB::FILE_OPEN;
	c$smb_state$current_cmd$referenced_file$fid = file_id;
	c$smb_state$current_cmd$referenced_file$size = file_size;

	# I'm seeing negative data from IPC tree transfers
	if ( time_to_double(times$modified) > 0.0 )
		c$smb_state$current_cmd$referenced_file$times = times;
	
	# We can identify the file by its file id now so let's stick it 
	# in the file map.
	c$smb_state$fid_map[file_id] = c$smb_state$current_cmd$referenced_file;
	
	c$smb_state$current_file = c$smb_state$fid_map[file_id];
	
	SMB::write_file_log(c$smb_state$current_file);
	}
	
event smb1_read_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id);
	c$smb_state$current_file$action = SMB::FILE_READ;
	c$smb_state$current_cmd$argument = c$smb_state$current_file$name;
	}
	
event smb1_read_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, length: count) &priority=-5
	{
	if ( c$smb_state$current_tree?$path && !c$smb_state$current_file?$path )
		c$smb_state$current_file$path = c$smb_state$current_tree$path;

	# TODO - Why is this commented out?
	#write_file_log(c$smb_state$current_file);
	}
	
event smb1_read_andx_response(c: connection, hdr: SMB1::Header, data_len: count) &priority=5
	{
	if ( c$smb_state$current_cmd$status !in SMB::ignored_command_statuses )
		{
		Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
		}
	}

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id);
	c$smb_state$current_file$action = SMB::FILE_WRITE;
	if ( !c$smb_state$current_cmd?$argument )
		c$smb_state$current_cmd$argument = c$smb_state$current_file$name;
	}
	
event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=-5
	{
	if ( c$smb_state$current_tree?$path && !c$smb_state$current_file?$path )
		c$smb_state$current_file$path = c$smb_state$current_tree$path;

	# TODO - Why is this commented out?
	#write_file_log(c$smb_state$current_file);
	}

#event smb1_write_andx_response(c: connection, hdr: SMB1::Header, written_bytes: count) &priority=5
#	{
#	# TODO - determine what to do here
#	}

event smb1_close_request(c: connection, hdr: SMB1::Header, file_id: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id);
	c$smb_state$current_file$action = SMB::FILE_CLOSE;
	}

event smb1_close_request(c: connection, hdr: SMB1::Header, file_id: count) &priority=-5
	{
	if ( file_id in c$smb_state$fid_map )
		{
		local fl = c$smb_state$fid_map[file_id];
		# Need to check for existence of path in case tree connect message wasn't seen.
		if ( c$smb_state$current_tree?$path )
			fl$path = c$smb_state$current_tree$path;

		c$smb_state$current_cmd$argument = fl$name;
		
		delete c$smb_state$fid_map[file_id];

		SMB::write_file_log(fl);
		}
	else
		{
		# TODO - Determine correct action
		# A reporter message is not right...
		#Reporter::warning("attempting to close an unknown file!");
		}
	}

event smb1_trans2_get_dfs_referral_request(c: connection, hdr: SMB1::Header, file_name: string, max_referral_level: count)
	{
	c$smb_state$current_cmd$argument = file_name;
	}

event smb1_trans2_query_path_info_request(c: connection, hdr: SMB1::Header, file_name: string, level_of_interets: count)
	{
	c$smb_state$current_cmd$argument = file_name;
	}

event smb1_trans2_find_first2_request(c: connection, hdr: SMB1::Header, args: SMB1::Find_First2_Request_Args)
	{
	c$smb_state$current_cmd$argument = args$file_name;
	}
	
event smb1_session_setup_andx_response(c: connection, hdr: SMB1::Header, response: SMB1::SessionSetupAndXResponse) &priority=-5
	{
	if ( c$smb_state$current_cmd$status !in SMB::ignored_command_statuses )
		{
		Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
		}
	}
	
event smb_ntlm_negotiate(c: connection, hdr: SMB1::Header, request: SMB::NTLMNegotiate)
	{
	c$smb_state$current_cmd$sub_command = "NTLMSSP_NEGOTIATE";
	}

event smb1_error(c: connection, hdr: SMB1::Header, is_orig: bool)
	{
	if ( ! is_orig )
		{
		# This is for deferred commands only.
		# The more specific messages won't fire for errors
		if ( ( c$smb_state$current_cmd$status !in SMB::ignored_command_statuses ) &&
		     ( c$smb_state$current_cmd$command in SMB::deferred_logging_cmds ) )
			{
			Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
			}
		}
	}
	
event smb_ntlm_authenticate(c: connection, hdr: SMB1::Header, request: SMB::NTLMAuthenticate)
	{
	c$smb_state$current_cmd$sub_command = "NTLMSSP_AUTHENTICATE";

	local user: string = "";
	if ( ( request?$domain_name && request$domain_name != "" ) && ( request?$user_name && request$user_name != "" ) )
		user = fmt("%s\\%s", request$domain_name, request$user_name);	
	else if ( ( request?$workstation && request$workstation != "" ) && ( request?$user_name && request$user_name != "" ) )
		user = fmt("%s\\%s", request$workstation, request$user_name);
	else if ( request?$user_name && request$user_name != "" )
		user = request$user_name;
	else if ( request?$domain_name && request$domain_name != "" )
		user = fmt("%s\\", request$domain_name);
	else if ( request?$workstation && request$workstation != "" )
		user = fmt("%s", request$workstation);

	if ( user != "" )
		{
		c$smb_state$current_cmd$argument = user;
		}

	if ( hdr$uid !in c$smb_state$uid_map )
		{
		c$smb_state$uid_map[hdr$uid] = user;
		}
	}

event smb1_transaction_request(c: connection, hdr: SMB1::Header, name: string, sub_cmd: count)
	{
	c$smb_state$current_cmd$sub_command = SMB1::trans_sub_commands[sub_cmd];
	}

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count)
	{
	c$smb_state$pipe_map[file_id] = c$smb_state$current_file$uuid;
	}

event smb_pipe_bind_ack_response(c: connection, hdr: SMB1::Header)
	{
	c$smb_state$current_cmd$sub_command = "RPC_BIND_ACK";
	c$smb_state$current_cmd$argument = SMB::rpc_uuids[c$smb_state$current_file$uuid];	
	}
	
event smb_pipe_bind_request(c: connection, hdr: SMB1::Header, uuid: string, version: string)
	{
	c$smb_state$current_cmd$sub_command = "RPC_BIND";
	c$smb_state$current_file$uuid = uuid;
	c$smb_state$current_cmd$argument = fmt("%s v%s", SMB::rpc_uuids[uuid], version);
	}

event smb_pipe_request(c: connection, hdr: SMB1::Header, op_num: count)
	{
	c$smb_state$current_cmd$argument = fmt("%s: %s", SMB::rpc_uuids[c$smb_state$current_file$uuid],
									   				 SMB::rpc_sub_cmds[c$smb_state$current_file$uuid][op_num]);
	}
	
#event smb1_transaction_setup(c: connection, hdr: SMB1::Header, op_code: count, file_id: count)
#	{
#	local uuid = SMB::rpc_uuids[c$smb_state$pipe_map[file_id]];
#	if ( uuid in SMB::rpc_uuids )
#		{
#		print fmt("smb1_transaction_setup %s", SMB::rap_cmds[op_code]);
#		}
#	}