refine connection SMB_Conn += {

	function proc_smb2_create_request(h: SMB2_Header, val: SMB2_create_request): bool
		%{
		if ( smb2_create_request )
			{
			BifEvent::generate_smb2_create_request(bro_analyzer(),
			                                       bro_analyzer()->Conn(),
			                                       BuildSMB2HeaderVal(h),
			                                       smb2_string2stringval(${val.filename}));
			}

		return true;
		%}

	function proc_smb2_create_response(h: SMB2_Header, val: SMB2_create_response): bool
		%{
		if ( smb2_create_response )
			{
			BifEvent::generate_smb2_create_response(bro_analyzer(), 
			                                        bro_analyzer()->Conn(),
			                                        BuildSMB2HeaderVal(h),
			                                        BuildSMB2GUID(${val.file_id}),
			                                        ${val.eof},
			                                        SMB_BuildMACTimes(${val.last_write_time}, 
			                                                          ${val.last_access_time}, 
			                                                          ${val.creation_time}, 
			                                                          ${val.change_time}),
			                                        smb2_file_attrs_to_bro(${val.file_attrs}));
			}

		if ( ${val.eof} > 0 )
			{
			file_mgr->SetSize(${val.eof}, 
			                  bro_analyzer()->GetAnalyzerTag(),
			                  bro_analyzer()->Conn(),
			                  h->is_orig());
			}

		return true;
		%}
};

type SMB2_create_context = record {
	next_offset       : uint32;
	name_offset       : uint16;
	name_len          : uint16;
	reserved          : uint16;
	data_offset       : uint16;
	data_len          : uint32;
	name_pad          : padding to name_offset;
	name              : SMB2_string(name_len);
	data_pad          : padding to data_offset;
	data              : SMB2_string(data_len);
	next_context_pad  : padding to next_offset;
};

type SMB2_create_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	sec_flags_reserved  : uint8;  # ignored
	oplock              : uint8;
	impersonation_level : uint32;
	flags               : bytestring &length=8; # ignored
	reserved            : bytestring &length=8; # ignored
	access_mask         : uint32;
	file_attrs          : SMB2_file_attributes;
	share_access        : uint32;
	disposition         : uint32;
	create_options      : uint32;
	filename_offset     : uint16;
	filename_len        : uint16;
	context_offset      : uint32;
	context_len         : uint32;
	filename_pad        : padding to filename_offset - header.head_length;
	filename            : SMB2_string(filename_len);
	# If there are no context records, the context_offset will
	# be set to zero so we need to deal with that to avoid
	# negative wrap around in the padding.
	context_pad         : padding to (context_offset==0 ? 0 : context_offset - header.head_length);
	create : case context_len of {
		0       -> blank    : empty;
		default -> contexts : SMB2_create_context[] &length=context_len;
	};
} &let {
	proc : bool = $context.connection.proc_smb2_create_request(header, this);
};


type SMB2_create_response(header: SMB2_Header) = record {
	structure_size   : uint16;
	oplock           : uint8;
	reserved         : uint8;
	create_action    : uint32;
	creation_time    : SMB_timestamp;
	last_access_time : SMB_timestamp;
	last_write_time  : SMB_timestamp;
	change_time      : SMB_timestamp;
	alloc_size       : uint64;
	eof              : uint64;
	file_attrs       : SMB2_file_attributes;
	reserved2        : uint32;
	file_id          : SMB2_guid;
	context_offset   : uint32;
	context_len      : uint32;
	# If there are no context records, the context_offset will
	# be set to zero so we need to deal with that to avoid
	# negative wrap around in the padding.
	context_pad      : padding to (context_offset==0 ? 0 : context_offset - header.head_length);
	create : case context_len of {
		0       -> blank    : empty;
		default -> contexts : SMB2_create_context[] &length=context_len;
	};
} &let {
	proc : bool = $context.connection.proc_smb2_create_response(header, this);
};
