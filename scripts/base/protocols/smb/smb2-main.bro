module SMB2;

redef record SMB::CmdInfo += {
	## Dialects offered by the client	
	smb2_offered_dialects: index_vec &optional;
};

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=5
	{
	if ( ! c?$smb_state )
		{
		local state: SMB::State;
		state$fid_map = table();
		state$tid_map = table();
		state$pending_cmds = table();
		c$smb_state = state;
		}
	
	local smb_state = c$smb_state;
	local tid = hdr$tree_id;
	local pid = hdr$process_id;
	local mid = hdr$message_id;
	local sid = hdr$session_id;
	
	if ( tid !in smb_state$tid_map )
		{
		local tmp_tree: SMB::TreeInfo = [$uid=c$uid, $id=c$id];
		smb_state$tid_map[tid] = tmp_tree;
		}
	smb_state$current_tree = smb_state$tid_map[tid];
	
	if ( mid !in smb_state$pending_cmds )
		{
		local tmp_cmd: SMB::CmdInfo = [$ts=network_time(), $uid=c$uid, $id=c$id, $version="SMB2", $command = SMB2::commands[hdr$command]];

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

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=-5
	{
	# Is this a response?
	if ( !is_orig )
		{
		if ( ( c$smb_state$current_cmd$status !in SMB::ignored_command_statuses ) &&
		     ( c$smb_state$current_cmd$command !in SMB::deferred_logging_cmds ) )
			{
			Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
			}
		delete c$smb_state$pending_cmds[hdr$message_id];
		}
	}

event smb2_negotiate_request(c: connection, hdr: SMB2::Header, dialects: index_vec) &priority=5
	{
	c$smb_state$current_cmd$smb2_offered_dialects = dialects;
	}

event smb2_negotiate_response(c: connection, hdr: SMB2::Header, response: SMB2::NegotiateResponse) &priority=5
	{
	if ( c$smb_state$current_cmd?$smb2_offered_dialects )
		{
		for ( i in c$smb_state$current_cmd$smb2_offered_dialects )
			{
			if ( response$dialect_revision == c$smb_state$current_cmd$smb2_offered_dialects[i] )
				{
				c$smb_state$current_cmd$argument = SMB2::dialects[response$dialect_revision];
				break;
				}
			}
		delete c$smb_state$current_cmd$smb2_offered_dialects;
		}
	}

event smb2_negotiate_response(c: connection, hdr: SMB2::Header, response: SMB2::NegotiateResponse) &priority=5
	{
	if ( c$smb_state$current_cmd$status !in SMB::ignored_command_statuses )
		{
		Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
		}	
	}
	
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=5
	{
	local tmp_tree: SMB::TreeInfo = [$ts=network_time(), $uid=c$uid, $id=c$id, $path=path];

	c$smb_state$current_cmd$referenced_tree = tmp_tree;
	}

event smb2_tree_connect_response(c: connection, hdr: SMB2::Header, response: SMB2::TreeConnectResponse) &priority=5
	{
	c$smb_state$current_cmd$referenced_tree$share_type = SMB2::share_types[response$share_type];
	c$smb_state$current_tree = c$smb_state$current_cmd$referenced_tree;
	c$smb_state$tid_map[hdr$tree_id] = c$smb_state$current_tree;
	}

event smb2_tree_connect_response(c: connection, hdr: SMB2::Header, response: SMB2::TreeConnectResponse) &priority=-5
	{
	Log::write(SMB::MAPPING_LOG, c$smb_state$current_tree);
	}

event smb2_create_request(c: connection, hdr: SMB2::Header, name: string) &priority=5
	{
	local tmp_file: SMB::FileInfo = [$ts=network_time(), $uid=c$uid, $id=c$id];
	c$smb_state$current_cmd$referenced_file = tmp_file;
	c$smb_state$current_cmd$referenced_file$name = name;
	c$smb_state$current_cmd$referenced_file$action = SMB::FILE_OPEN;
	c$smb_state$current_file = c$smb_state$current_cmd$referenced_file;
	}

event smb2_create_response(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, file_size: count, times: SMB::MACTimes, attrs: SMB2::FileAttrs) &priority=5
	{
	c$smb_state$current_cmd$referenced_file$action = SMB::FILE_OPEN;
	c$smb_state$current_cmd$referenced_file$fid = file_id$persistent+file_id$volatile;
	c$smb_state$current_cmd$referenced_file$size = file_size;

	# I'm seeing negative data from IPC tree transfers
	if ( time_to_double(times$modified) > 0.0 )
		c$smb_state$current_cmd$referenced_file$times = times;
	
	# We can identify the file by its file id now so let's stick it 
	# in the file map.
	c$smb_state$fid_map[file_id$persistent+file_id$volatile] = c$smb_state$current_cmd$referenced_file;
	
	c$smb_state$current_file = c$smb_state$fid_map[file_id$persistent+file_id$volatile];
	
	SMB::write_file_log(c$smb_state$current_file);
	}

event smb2_read_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);
	c$smb_state$current_file$action = SMB::FILE_READ;
	}

event smb2_read_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=-5
	{ 
	if ( c$smb_state$current_tree?$path && !c$smb_state$current_file?$path )
		c$smb_state$current_file$path = c$smb_state$current_tree$path;

	# TODO - Why is this commented out?
	#write_file_log(c$smb_state$current_file);
	}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);
	c$smb_state$current_file$action = SMB::FILE_WRITE;
	}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=-5
	{
	if ( c$smb_state$current_tree?$path && ! c$smb_state$current_file?$path )
		c$smb_state$current_file$path = c$smb_state$current_tree$path;

	# TODO - Why is this commented out?
	#write_file_log(c$smb_state$current_file);
	}

event smb2_close_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);
	c$smb_state$current_file$action = SMB::FILE_CLOSE;
	}

event smb2_close_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID) &priority=-5
	{
	if ( file_id$persistent+file_id$volatile in c$smb_state$fid_map )
		{
		local fl = c$smb_state$fid_map[file_id$persistent+file_id$volatile];
		# Need to check for existence of path in case tree connect message wasn't seen.
		if ( c$smb_state$current_tree?$path )
			fl$path = c$smb_state$current_tree$path;
		delete c$smb_state$fid_map[file_id$persistent+file_id$volatile];

		SMB::write_file_log(fl);
		}
	else
		{
		# TODO - Determine correct action
		# A reporter message is not right...
		#Reporter::warning("attempting to close an unknown file!");
		}
	}
