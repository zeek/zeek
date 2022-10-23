@load ./main

module SMB2;

redef record SMB::CmdInfo += {
	## Dialects offered by the client.
	smb2_offered_dialects: index_vec &optional;

	## Keep the create_options in the command for
	## referencing later.
	smb2_create_options: count &default=0;
};

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=5
	{
	if ( ! c?$smb_state )
		{
		local state: SMB::State;
		state$fid_map = table();
		state$tid_map = table();
		state$uid_map = table();
		state$pending_cmds = table();
		state$pipe_map = table();
		c$smb_state = state;
		}

	local smb_state = c$smb_state;
	local tid = hdr$tree_id;
	local mid = hdr$message_id;

	if ( mid !in smb_state$pending_cmds )
		{
		local tmp_file = SMB::FileInfo($uid=c$uid, $id=c$id);
		local tmp_cmd = SMB::CmdInfo($uid=c$uid, $id=c$id, $version="SMB2", $command = SMB2::commands[hdr$command]);
		tmp_cmd$referenced_file = tmp_file;
		smb_state$pending_cmds[mid] = tmp_cmd;
		}
	smb_state$current_cmd = smb_state$pending_cmds[mid];

	if ( tid > 0 )
		{
		if ( smb_state$current_cmd?$referenced_tree )
			{
			smb_state$tid_map[tid] = smb_state$current_cmd$referenced_tree;
			}
		else if ( tid !in smb_state$tid_map )
			{
			local tmp_tree = SMB::TreeInfo($uid=c$uid, $id=c$id);
			smb_state$tid_map[tid] = tmp_tree;
			}
		smb_state$current_cmd$referenced_tree = smb_state$tid_map[tid];
		}
	else
		{
		smb_state$current_cmd$referenced_tree = SMB::TreeInfo($uid=c$uid, $id=c$id);
		}

	smb_state$current_file = smb_state$current_cmd$referenced_file;
	smb_state$current_tree = smb_state$current_cmd$referenced_tree;

	if ( !is_orig )
		{
		smb_state$current_cmd$rtt = network_time() - smb_state$current_cmd$ts;
		smb_state$current_cmd$status = SMB::statuses[hdr$status]$id;
		}
	}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=-5
	{
	if ( is_orig )
		return;

	# If the command that is being looked at right now was
	# marked as PENDING, then we'll skip all of this and wait
	# for a reply that isn't marked pending.
	if ( c$smb_state$current_cmd$status == "PENDING" )
		return;

	delete c$smb_state$pending_cmds[hdr$message_id];
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

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=5
	{
	c$smb_state$current_tree$path = path;
	}

event smb2_tree_connect_response(c: connection, hdr: SMB2::Header, response: SMB2::TreeConnectResponse) &priority=5
	{
	c$smb_state$current_tree$share_type = SMB2::share_types[response$share_type];
	}

event smb2_tree_connect_response(c: connection, hdr: SMB2::Header, response: SMB2::TreeConnectResponse) &priority=-5
	{
	Log::write(SMB::MAPPING_LOG, c$smb_state$current_tree);
	}

event smb2_tree_disconnect_request(c: connection, hdr: SMB2::Header) &priority=5
	{
	if ( hdr$tree_id in c$smb_state$tid_map )
		{
		delete c$smb_state$tid_map[hdr$tree_id];
		delete c$smb_state$current_tree;
		delete c$smb_state$current_cmd$referenced_tree;
		}
	}

event smb2_create_request(c: connection, hdr: SMB2::Header, request: SMB2::CreateRequest) &priority=5
	{
	if ( request$filename == "")
		request$filename = "<share_root>";

	c$smb_state$current_file$name = request$filename;
	c$smb_state$current_cmd$smb2_create_options = request$create_options;

	switch ( c$smb_state$current_tree$share_type )
		{
		case "DISK":
			c$smb_state$current_file$action = SMB::FILE_OPEN;
			break;
		case "PIPE":
			c$smb_state$current_file$action = SMB::PIPE_OPEN;
			break;
		case "PRINT":
			c$smb_state$current_file$action = SMB::PRINT_OPEN;
			break;
		default:
			c$smb_state$current_file$action = SMB::FILE_OPEN;
			break;
		}
	}

event smb2_create_response(c: connection, hdr: SMB2::Header, response: SMB2::CreateResponse) &priority=5
	{
	SMB::set_current_file(c$smb_state, response$file_id$persistent+response$file_id$volatile);

	c$smb_state$current_file$fid = response$file_id$persistent+response$file_id$volatile;
	c$smb_state$current_file$size = response$size;

	if ( c$smb_state$current_tree?$path )
		c$smb_state$current_file$path = c$smb_state$current_tree$path;

	# I'm seeing negative data from IPC tree transfers
	if ( time_to_double(response$times$modified) > 0.0 )
		c$smb_state$current_file$times = response$times;

	# We can identify the file by its file id now so let's stick it
	# in the file map.
	c$smb_state$fid_map[response$file_id$persistent+response$file_id$volatile] = c$smb_state$current_file;

	c$smb_state$current_file = c$smb_state$fid_map[response$file_id$persistent+response$file_id$volatile];

	# If the create request for this file had FILE_DELETE_ON_CLOSE set and
	# the response status was success, raise a smb2_file_delete event.
	if ( hdr$status == 0 && (c$smb_state$current_cmd$smb2_create_options & 0x00001000) != 0 )
		event smb2_file_delete(c, hdr, response$file_id, T);
	}

event smb2_create_response(c: connection, hdr: SMB2::Header, response: SMB2::CreateResponse) &priority=-5
	{
	SMB::write_file_log(c$smb_state);
	}

event smb2_read_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);

	switch ( c$smb_state$current_tree$share_type )
		{
		case "DISK":
			c$smb_state$current_file$action = SMB::FILE_READ;
			break;
		case "PIPE":
			c$smb_state$current_file$action = SMB::PIPE_READ;
			break;
		case "PRINT":
			c$smb_state$current_file$action = SMB::PRINT_READ;
			break;
		default:
			c$smb_state$current_file$action = SMB::FILE_READ;
			break;
		}
	}

event smb2_read_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=-5
	{
	SMB::write_file_log(c$smb_state);
	}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);

	switch ( c$smb_state$current_tree$share_type )
		{
		case "DISK":
			c$smb_state$current_file$action = SMB::FILE_WRITE;
			break;
		case "PIPE":
			c$smb_state$current_file$action = SMB::PIPE_WRITE;
			break;
		case "PRINT":
			c$smb_state$current_file$action = SMB::PRINT_WRITE;
			break;
		default:
			c$smb_state$current_file$action = SMB::FILE_WRITE;
			break;
		}
	}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=-5
	{
	SMB::write_file_log(c$smb_state);
	}

event smb2_file_sattr(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, times: SMB::MACTimes, attrs: SMB2::FileAttrs) &priority=-5
	{
	SMB::write_file_log(c$smb_state);
	}

event smb2_file_sattr(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, times: SMB::MACTimes, attrs: SMB2::FileAttrs) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);

	switch ( c$smb_state$current_tree$share_type )
		{
		case "DISK":
			c$smb_state$current_file$action = SMB::FILE_SET_ATTRIBUTE;
			break;
		default:
			c$smb_state$current_file$action = SMB::FILE_SET_ATTRIBUTE;
			break;
		}
	}

event smb2_file_rename(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, dst_filename: string) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);

	if ( c$smb_state$current_file?$name )
		c$smb_state$current_file$prev_name = c$smb_state$current_file$name;

	c$smb_state$current_file$name = dst_filename;

	switch ( c$smb_state$current_tree$share_type )
		{
		case "DISK":
			c$smb_state$current_file$action = SMB::FILE_RENAME;
			break;
		default:
			c$smb_state$current_file$action = SMB::FILE_RENAME;
			break;
		}
	}

event smb2_file_rename(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, dst_filename: string) &priority=-5
	{
	SMB::write_file_log(c$smb_state);
	}

event smb2_file_delete(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, delete_pending: bool) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);

	if ( ! delete_pending )
		{
		# This is weird because it would mean that someone didn't
		# set the delete bit in a delete request.
		return;
		}

	switch ( c$smb_state$current_tree$share_type )
		{
		case "DISK":
			c$smb_state$current_file$action = SMB::FILE_DELETE;
			break;
		default:
			c$smb_state$current_file$action = SMB::FILE_DELETE;
			break;
		}
	}

event smb2_file_delete(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, delete_pending: bool) &priority=-5
	{
	SMB::write_file_log(c$smb_state);
	}

event smb2_close_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id$persistent+file_id$volatile);

	switch ( c$smb_state$current_tree$share_type )
		{
		case "DISK":
			c$smb_state$current_file$action = SMB::FILE_CLOSE;
			break;
		case "PIPE":
			c$smb_state$current_file$action = SMB::PIPE_CLOSE;
			break;
		case "PRINT":
			c$smb_state$current_file$action = SMB::PRINT_CLOSE;
			break;
		default:
			c$smb_state$current_file$action = SMB::FILE_CLOSE;
			break;
		}
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

		SMB::write_file_log(c$smb_state);
		}
	else
		{
		# TODO - Determine correct action
		# A reporter message is not right...
		#Reporter::warning("attempting to close an unknown file!");
		}
	}
