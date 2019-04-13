refine connection SMB_Conn += {

	function proc_smb2_create_request(h: SMB2_Header, val: SMB2_create_request): bool
		%{
		StringVal *filename = smb2_string2stringval(${val.filename});
		if ( ! ${h.is_pipe} &&
		     BifConst::SMB::pipe_filenames->AsTable()->Lookup(filename->CheckString()) )
			{
			set_tree_is_pipe(${h.tree_id});
			BifEvent::generate_smb_pipe_connect_heuristic(bro_analyzer(),
			                                              bro_analyzer()->Conn());
			}

		if ( smb2_create_request )
			{
			RecordVal* requestinfo = new RecordVal(BifType::Record::SMB2::CreateRequest);
			requestinfo->Assign(0, filename);
			requestinfo->Assign(1, val_mgr->GetCount(${val.disposition}));
			requestinfo->Assign(2, val_mgr->GetCount(${val.create_options}));
			requestinfo->Assign(3, val_mgr->GetCount(${val.access_mask}));
			BifEvent::generate_smb2_create_request(bro_analyzer(),
			                                       bro_analyzer()->Conn(),
			                                       BuildSMB2HeaderVal(h),
			                                       requestinfo);
			}
		else
			{
			delete filename;
			}

		return true;
		%}

	function proc_smb2_create_response(h: SMB2_Header, val: SMB2_create_response): bool
		%{
		if ( smb2_create_response )
			{
			RecordVal* responseinfo = new RecordVal(BifType::Record::SMB2::CreateResponse);
			responseinfo->Assign(0, BuildSMB2GUID(${val.file_id}));
			responseinfo->Assign(1, val_mgr->GetCount(${val.eof}));
			responseinfo->Assign(2, SMB_BuildMACTimes(${val.last_write_time},
			                                          ${val.last_access_time},
			                                          ${val.creation_time},
			                                          ${val.change_time}));
			responseinfo->Assign(3, smb2_file_attrs_to_bro(${val.file_attrs}));
			responseinfo->Assign(4, val_mgr->GetCount(${val.create_action}));
			BifEvent::generate_smb2_create_response(bro_analyzer(),
			                                        bro_analyzer()->Conn(),
			                                        BuildSMB2HeaderVal(h),
			                                        responseinfo);
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
	# The strings with +2 are to account for terminating null bytes (UTF-16 NULLS)
	# TODO-I'm not sure if what I'm doing here is correct.  This may need to be
	# evaluated still.
	name              : SMB2_string(name_len==0 ? 2 : name_len);
	data_pad          : padding to data_offset;
	data              : SMB2_string(data_len==0 ? 2 : data_len);
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
	# TODO: skip this data for now.  It's shown to be a bit difficult.
	#create : case context_len of {
	#	0       -> blank    : empty;
	#	default -> contexts : SMB2_create_context[] &length=context_len;
	#};
	contexts : bytestring &length=context_len &transient;
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
	# TODO: skip this data for now.  It's shown to be a bit difficult.
	#create : case context_len of {
	#	0       -> blank    : empty;
	#	default -> contexts : SMB2_create_context[] &length=context_len;
	#};
	contexts : bytestring &length=context_len &transient;
} &let {
	proc : bool = $context.connection.proc_smb2_create_response(header, this);
};
