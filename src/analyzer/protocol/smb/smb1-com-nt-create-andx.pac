refine connection SMB_Conn += {
	function proc_smb1_nt_create_andx_request(header: SMB_Header, val: SMB1_nt_create_andx_request): bool
		%{
		auto filename = smb_string2stringval(${val.filename});

		if ( ! ${header.is_pipe} &&
		     zeek::BifConst::SMB::pipe_filenames->AsTable()->Lookup(filename->CheckString()) )
			{
			set_tree_is_pipe(${header.tid});

			if ( smb_pipe_connect_heuristic )
				zeek::BifEvent::enqueue_smb_pipe_connect_heuristic(zeek_analyzer(),
				                                             zeek_analyzer()->Conn());
			}

		if ( smb1_nt_create_andx_request )
			{
			zeek::BifEvent::enqueue_smb1_nt_create_andx_request(zeek_analyzer(),
			                                              zeek_analyzer()->Conn(),
			                                              SMBHeaderVal(header),
			                                              std::move(filename));
			}

		return true;
		%}

	function proc_smb1_nt_create_andx_response(header: SMB_Header, val: SMB1_nt_create_andx_response): bool
		%{
		if ( smb1_nt_create_andx_response )
			{
			zeek::BifEvent::enqueue_smb1_nt_create_andx_response(zeek_analyzer(),
			                                               zeek_analyzer()->Conn(),
			                                               SMBHeaderVal(header),
			                                               ${val.file_id},
			                                               ${val.end_of_file},
			                                               SMB_BuildMACTimes(${val.last_write_time},
			                                                                 ${val.last_access_time},
			                                                                 ${val.create_time},
			                                                                 ${val.last_change_time}));
			}

		return true;
		%}

};


type SMB1_nt_create_andx_request(header: SMB_Header, offset: uint16) = record {
	word_count          : uint8;
	andx                : SMB_andx;
	reserved            : uint8;

	name_length         : uint16;
	flags               : uint32;
	root_dir_file_id    : uint32;
	desired_access      : uint32;
	alloc_size          : uint64;
	ext_file_attrs      : uint32;
	share_access        : uint32;
	create_disposition  : uint32;
	create_options      : uint32;
	impersonation_level : uint32;
	security_flags      : uint8;

	byte_count          : uint16;
	filename            : SMB_string(header.unicode, offsetof(filename));

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command        : SMB_andx_command(header, true, offset+offsetof(andx_command), andx.command);
} &let {
	proc : bool = $context.connection.proc_smb1_nt_create_andx_request(header, this);
};

type SMB1_nt_create_andx_response(header: SMB_Header, offset: uint16) = record {
	word_count         : uint8;
	andx               : SMB_andx;
	oplock_level       : uint8;
	file_id            : uint16;
	create_disposition : uint32;
	create_time        : SMB_timestamp;
	last_access_time   : SMB_timestamp;
	last_write_time    : SMB_timestamp;
	last_change_time   : SMB_timestamp;
	ext_file_attrs     : uint32;
	allocation_size    : uint64;
	end_of_file        : uint64;
	resource_type      : uint16;
	nm_pipe_status     : uint16;
	directory          : uint8;

	byte_count         : uint16;

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command       : SMB_andx_command(header, false, offset+offsetof(andx_command), andx.command);
} &let {
	proc : bool = $context.connection.proc_smb1_nt_create_andx_response(header, this);
};
