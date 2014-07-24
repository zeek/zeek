module SMB2;

redef record SMB::Info += {
	smb2_offered_dialects: index_vec &optional;
};

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=5
	{
	if ( ! c?$smb )
		{
		local info: SMB::Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $version="SMB2"];
		info$fid_map = table();
		info$tid_map = table();
		info$pending_cmds = table();
		c$smb = info;
		}
	
	local smb = c$smb;
	local tid = hdr$tree_id;
	local pid = hdr$process_id;
	local mid = hdr$message_id;
	local sid = hdr$session_id;
	
	if ( tid !in smb$tid_map )
		{
		local tmp_tree: SMB::TreeInfo = [$uid=c$uid, $id=c$id];
		smb$tid_map[tid] = tmp_tree;
		}
	smb$current_tree = smb$tid_map[tid];
	
	if ( mid !in smb$pending_cmds )
		{
		local tmp_cmd: SMB::CmdInfo;
		tmp_cmd$command = SMB2::commands[hdr$command];

		local tmp_file: SMB::FileInfo;
		tmp_file$ts = network_time();
		tmp_file$id = c$id;
		tmp_file$uid = c$uid;
		tmp_cmd$referenced_file = tmp_file;
		tmp_cmd$referenced_tree = smb$current_tree;
		
		smb$pending_cmds[mid] = tmp_cmd;
		}
	
	smb$current_cmd = smb$pending_cmds[mid];
	smb$command = smb$current_cmd$command;

	if ( is_orig )
		{
		smb$ts = network_time();
		}
	else
		{
		smb$rtt = network_time() - smb$ts;
		smb$status = SMB::statuses[hdr$status]$id;
		}
	}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=-5
	{
	if ( !is_orig )
		# This is a response and the command is no longer pending
		# so let's get rid of it.
		delete c$smb$pending_cmds[hdr$message_id];

	if ( c?$smb )
		Log::write(SMB::CMD_LOG, c$smb);
	}

event smb2_negotiate_request(c: connection, hdr: SMB2::Header, dialects: index_vec) &priority=5
	{
	c$smb$smb2_offered_dialects = dialects;
	}

event smb2_negotiate_response(c: connection, hdr: SMB2::Header, response: SMB2::NegotiateResponse)
	{
	if ( c$smb?$smb2_offered_dialects )
		{
		for ( i in c$smb$smb2_offered_dialects )
			{
			if ( response$dialect_revision == c$smb$smb2_offered_dialects[i] )
				{
				c$smb$dialect = SMB2::dialects[response$dialect_revision];
				break;
				}
			}
		delete c$smb$smb2_offered_dialects;
		}
	}

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=5
	{
	c$smb$current_cmd$referenced_tree$path = path;
	c$smb$current_tree$ts=network_time();
	}

event smb2_tree_connect_response(c: connection, hdr: SMB2::Header, response: SMB2::TreeConnectResponse) &priority=5
	{
	c$smb$current_tree = c$smb$current_cmd$referenced_tree;
	c$smb$current_tree$share_type = SMB2::share_types[response$share_type];
	c$smb$tid_map[hdr$tree_id] = c$smb$current_tree;
	}

event smb2_tree_connect_response(c: connection, hdr: SMB2::Header, response: SMB2::TreeConnectResponse) &priority=-5
	{
	Log::write(SMB::MAPPING_LOG, c$smb$current_tree);
	}

event smb2_create_request(c: connection, hdr: SMB2::Header, name: string) &priority=5
	{
	c$smb$current_cmd$referenced_file$name = name;
	c$smb$current_file = c$smb$current_cmd$referenced_file;
	c$smb$current_file$action = SMB::FILE_OPEN;
	}

event smb2_create_response(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, file_size: count, times: SMB::MACTimes, attrs: SMB2::FileAttrs) &priority=5
	{
	if ( ! c$smb?$current_file )
		{
		c$smb$current_file = c$smb$current_cmd$referenced_file;
		c$smb$current_file$action = SMB::FILE_OPEN;
		}
	c$smb$current_file$fid = file_id$persistent+file_id$volatile;
	c$smb$current_file$size = file_size;

	# I'm seeing negative data from IPC tree transfers
	if ( time_to_double(times$modified) > 0.0 )
		c$smb$current_file$times = times;
	
	# We can identify the file by its file id now so let's stick it 
	# in the file map.
	c$smb$fid_map[file_id$persistent+file_id$volatile] = c$smb$current_file;

	SMB::write_file_log(c$smb$current_file);
	}

event smb2_read_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb, file_id$persistent+file_id$volatile);
	c$smb$current_file$action = SMB::FILE_READ;

	if ( c$smb$current_tree?$path && !c$smb$current_file?$path )
		c$smb$current_file$path = c$smb$current_tree$path;

	#write_file_log(c$smb$current_file);
	}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb, file_id$persistent+file_id$volatile);
	c$smb$current_file$action = SMB::FILE_WRITE;

	if ( c$smb$current_tree?$path && ! c$smb$current_file?$path )
		c$smb$current_file$path = c$smb$current_tree$path;
	}

event smb2_close_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID) &priority=5
	{
	SMB::set_current_file(c$smb, file_id$persistent+file_id$volatile);
	c$smb$current_file$action = SMB::FILE_CLOSE;
	}

event smb2_close_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID) &priority=-5
	{
	if ( file_id$persistent+file_id$volatile in c$smb$fid_map )
		{
		local fl = c$smb$fid_map[file_id$persistent+file_id$volatile];
		fl$uid = c$uid;
		fl$id = c$id;
		# Need to check for existence of path in case tree connect message wasn't seen.
		if ( c$smb$current_tree?$path )
			fl$path = c$smb$current_tree$path;
		delete c$smb$fid_map[file_id$persistent+file_id$volatile];

		SMB::write_file_log(fl);
		}
	else
		{
		# A reporter message is not right...
		#Reporter::warning("attempting to close an unknown file!");
		}
	}
