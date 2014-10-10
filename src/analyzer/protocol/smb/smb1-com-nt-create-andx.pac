refine connection SMB_Conn += {
	function proc_smb1_nt_create_andx_request(header: SMB_Header, val: SMB1_nt_create_andx_request): bool
		%{
		if ( smb1_nt_create_andx_request )
			{
			// name_length         : uint16;
			// flags               : uint32;
			// root_dir_file_id    : uint32;
			// desired_access      : uint32;
			// alloc_size          : uint64;
			// ext_file_attrs      : uint32;
			// share_access        : uint32;
			// create_disposition  : uint32;
			// create_options      : uint32;
			// impersonation_level : uint32;
			// security_flags      : uint8;
			// 
			// byte_count          : uint16;
			// filename            : SMB_string(header.unicode, offsetof(filename)) &length=name_length;

			BifEvent::generate_smb1_nt_create_andx_request(bro_analyzer(),
			                                              bro_analyzer()->Conn(),
			                                              BuildHeaderVal(header),
			                                              smb_string2stringval(${val.filename}));
			}
		return true;
		%}

	function proc_smb1_nt_create_andx_response(header: SMB_Header, val: SMB1_nt_create_andx_response): bool
		%{
		if ( smb1_nt_create_andx_response )
			{
			BifEvent::generate_smb1_nt_create_andx_response(bro_analyzer(),
			                                               bro_analyzer()->Conn(),
			                                               BuildHeaderVal(header),
			                                               ${val.file_id},
			                                               ${val.end_of_file},
			                                               SMB_BuildMACTimes(${val.last_write_time},
			                                                                 ${val.last_access_time},
			                                                                 ${val.create_time},
			                                                                 ${val.last_change_time}));
			}

		if ( ${val.end_of_file} > 0 )
			{
			file_mgr->SetSize(${val.end_of_file}, 
			                  bro_analyzer()->GetAnalyzerTag(),
			                  bro_analyzer()->Conn(),
			                  header->is_orig());
			}

		return true;
		%}

};


type SMB1_nt_create_andx_request(header: SMB_Header) = record {
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
	
	andx_command        : SMB_andx_command(header, 1, andx.command);
} &let {
	proc : bool = $context.connection.proc_smb1_nt_create_andx_request(header, this);
};

type SMB1_nt_create_andx_response(header: SMB_Header) = record {
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
} &let {
	proc : bool = $context.connection.proc_smb1_nt_create_andx_response(header, this);
};
