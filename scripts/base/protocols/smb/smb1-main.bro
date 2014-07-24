module SMB1;

redef record SMB::Info += {
	smb1_offered_dialects: string_vec &optional;
};

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=5
	{
	if ( ! c?$smb )
		{
		local info: SMB::Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $version="SMB1"];
		info$fid_map = table();
		info$tid_map = table();
		info$pending_cmds = table();
		c$smb = info;
		}
	
	local smb = c$smb;
	local tid = hdr$tid;
	local pid = hdr$pid;
	local uid = hdr$uid;
	local mid = hdr$mid;
	
	if ( tid !in smb$tid_map )
		{
		local tmp_tree: SMB::TreeInfo = [$uid=c$uid, $id=c$id];
		smb$tid_map[tid] = tmp_tree;
		}
	smb$current_tree = smb$tid_map[tid];
	
	if ( mid !in smb$pending_cmds )
		{
		local tmp_cmd: SMB::CmdInfo;
		tmp_cmd$command = SMB1::commands[hdr$command];

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

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-5
	{
	if ( !is_orig )
		# This is a response and the command is no longer pending
		# so let's get rid of it.
		delete c$smb$pending_cmds[hdr$mid];

	if ( c?$smb )
		Log::write(SMB::CMD_LOG, c$smb);
	}


event smb1_negotiate_request(c: connection, hdr: SMB1::Header, dialects: string_vec) &priority=5
	{
	c$smb$smb1_offered_dialects = dialects;
	}

event smb1_negotiate_response(c: connection, hdr: SMB1::Header, response: SMB1::NegotiateResponse) &priority=5
	{
	if ( c$smb?$smb1_offered_dialects )
		{
		if ( response?$ntlm )
			c$smb$dialect = c$smb$smb1_offered_dialects[response$ntlm$dialect_index];
		delete c$smb$smb1_offered_dialects;
		}
	}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) &priority=5
	{
	c$smb$current_cmd$referenced_tree$path = path;
	c$smb$current_cmd$referenced_tree$service = service;
	c$smb$current_tree$ts=network_time();
	}

event smb1_tree_connect_andx_response(c: connection, hdr: SMB1::Header, service: string, native_file_system: string) &priority=5
	{
	c$smb$current_cmd$referenced_tree$native_file_system = native_file_system;
	c$smb$current_tree = c$smb$current_cmd$referenced_tree;
	c$smb$tid_map[hdr$tid] = c$smb$current_tree;
	}

event smb1_tree_connect_andx_response(c: connection, hdr: SMB1::Header, service: string, native_file_system: string) &priority=-5
	{
	Log::write(SMB::MAPPING_LOG, c$smb$current_tree);
	}

event smb1_nt_create_andx_request(c: connection, hdr: SMB1::Header, name: string) &priority=5
	{
	c$smb$current_cmd$referenced_file$name = name;
	c$smb$current_file = c$smb$current_cmd$referenced_file;
	c$smb$current_file$action = SMB::FILE_OPEN;
	}

event smb1_nt_create_andx_response(c: connection, hdr: SMB1::Header, file_id: count, file_size: count, times: SMB::MACTimes) &priority=5
	{
	if ( ! c$smb?$current_file )
		{
		c$smb$current_file = c$smb$current_cmd$referenced_file;
		c$smb$current_file$action = SMB::FILE_OPEN;
		}
	c$smb$current_file$fid = file_id;
	c$smb$current_file$size = file_size;

	# I'm seeing negative data from IPC tree transfers
	if ( time_to_double(times$modified) > 0.0 )
		c$smb$current_file$times = times;
	
	# We can identify the file by its file id now so let's stick it 
	# in the file map.
	c$smb$fid_map[file_id] = c$smb$current_file;

	SMB::write_file_log(c$smb$current_file);
	}
	
event smb1_read_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb, file_id);
	c$smb$current_file$action = SMB::FILE_READ;

	if ( c$smb$current_tree?$path && !c$smb$current_file?$path )
		c$smb$current_file$path = c$smb$current_tree$path;

	#write_file_log(c$smb$current_file);
	}
	
event smb1_read_andx_response(c: connection, hdr: SMB1::Header, data_len: count) &priority=5
	{
	#print "read andx response!";
	}

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=5
	{
	SMB::set_current_file(c$smb, file_id);
	c$smb$current_file$action = SMB::FILE_WRITE;
	}
	
event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=-5
	{
	if ( c$smb$current_tree?$path && !c$smb$current_file?$path )
		c$smb$current_file$path = c$smb$current_tree$path;

	#write_file_log(c$smb$current_file);
	}

#event smb1_write_andx_response(c: connection, hdr: SMB1::Header, written_bytes: count) &priority=5
#	{
#	# Do i really need to do anything here?  Maybe do a weird if the number of bytes written is odd?
#	}

event smb1_close_request(c: connection, hdr: SMB1::Header, file_id: count) &priority=5
	{
	SMB::set_current_file(c$smb, file_id);
	c$smb$current_file$action = SMB::FILE_CLOSE;
	}

event smb1_close_request(c: connection, hdr: SMB1::Header, file_id: count) &priority=-5
	{
	if ( file_id in c$smb$fid_map )
		{
		local fl = c$smb$fid_map[file_id];
		fl$uid = c$uid;
		fl$id = c$id;
		# Need to check for existence of path in case tree connect message wasn't seen.
		if ( c$smb$current_tree?$path )
			fl$path = c$smb$current_tree$path;
		delete c$smb$fid_map[file_id];

		SMB::write_file_log(fl);
		}
	else
		{
		# A reporter message is not right...
		#Reporter::warning("attempting to close an unknown file!");
		}
	}
