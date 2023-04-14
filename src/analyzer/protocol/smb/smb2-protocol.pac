# Documentation for SMB2 protocol from here:
#     http://msdn.microsoft.com/en-us/library/cc246497(v=PROT.13).aspx

%header{
zeek::RecordValPtr BuildSMB2HeaderVal(SMB2_Header* hdr);
zeek::RecordValPtr BuildSMB2GUID(SMB2_guid* file_id);
zeek::RecordValPtr smb2_file_attrs_to_zeek(SMB2_file_attributes* val);
zeek::RecordValPtr BuildSMB2ContextVal(SMB3_negotiate_context_value* ncv);
%}

%code{
zeek::RecordValPtr BuildSMB2HeaderVal(SMB2_Header* hdr)
	{
	auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::Header);
	r->Assign(0, ${hdr.credit_charge});
	r->Assign(1, ${hdr.status});
	r->Assign(2, ${hdr.command});
	r->Assign(3, ${hdr.credits});
	r->Assign(4, ${hdr.flags});
	r->Assign(5, ${hdr.message_id});
	r->Assign(6, ${hdr.process_id});
	r->Assign(7, ${hdr.tree_id});
	r->Assign(8, ${hdr.session_id});
	r->Assign(9, to_stringval(${hdr.signature}));
	return r;
	}

zeek::RecordValPtr BuildSMB2GUID(SMB2_guid* file_id)
	{
	auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::GUID);
	r->Assign(0, ${file_id.persistent});
	r->Assign(1, ${file_id._volatile});
	return r;
	}

zeek::RecordValPtr smb2_file_attrs_to_zeek(SMB2_file_attributes* val)
	{
	auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::FileAttrs);
	r->Assign(0, ${val.read_only});
	r->Assign(1, ${val.hidden});
	r->Assign(2, ${val.system});
	r->Assign(3, ${val.directory});
	r->Assign(4, ${val.archive});
	r->Assign(5, ${val.normal});
	r->Assign(6, ${val.temporary});
	r->Assign(7, ${val.sparse_file});
	r->Assign(8, ${val.reparse_point});
	r->Assign(9, ${val.compressed});
	r->Assign(10, ${val.offline});
	r->Assign(11, ${val.not_content_indexed});
	r->Assign(12, ${val.encrypted});
	r->Assign(13, ${val.integrity_stream});
	r->Assign(14, ${val.no_scrub_data});
	return r;
	}

zeek::RecordValPtr BuildSMB2ContextVal(SMB3_negotiate_context_value* ncv)
	{
	auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::NegotiateContextValue);

	r->Assign(0, ${ncv.context_type});
	r->Assign(1, ${ncv.data_length});

	switch ( ${ncv.context_type} ) {
	case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
		{
		auto rpreauth = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::PreAuthIntegrityCapabilities);
		rpreauth->Assign(0, ${ncv.preauth_integrity_capabilities.hash_alg_count});
		rpreauth->Assign(1, ${ncv.preauth_integrity_capabilities.salt_length});

		auto ha = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);

		for ( int i = 0; i < ${ncv.preauth_integrity_capabilities.hash_alg_count}; ++i )
			{
			const auto& vec = *${ncv.preauth_integrity_capabilities.hash_alg};
			ha->Assign(i, zeek::val_mgr->Count(vec[i]));
			}

		rpreauth->Assign(2, std::move(ha));
		rpreauth->Assign(3, to_stringval(${ncv.preauth_integrity_capabilities.salt}));
		r->Assign(2, std::move(rpreauth));
		}
		break;

	case SMB2_ENCRYPTION_CAPABILITIES:
		{
		auto rencr = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::EncryptionCapabilities);
		rencr->Assign(0, ${ncv.encryption_capabilities.cipher_count});

		auto c = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);

		for ( int i = 0; i < ${ncv.encryption_capabilities.cipher_count}; ++i )
			{
			const auto& vec = *${ncv.encryption_capabilities.ciphers};
			c->Assign(i, zeek::val_mgr->Count(vec[i]));
			}

		rencr->Assign(1, std::move(c));
		r->Assign(3, std::move(rencr));
		}
		break;

	case SMB2_COMPRESSION_CAPABILITIES:
		{
		auto rcomp = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::CompressionCapabilities);
		rcomp->Assign(0, ${ncv.compression_capabilities.alg_count});

		auto c = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);

		for ( int i = 0; i < ${ncv.compression_capabilities.alg_count}; ++i )
			{
			const auto& vec = *${ncv.compression_capabilities.algs};
			c->Assign(i, zeek::val_mgr->Count(vec[i]));
			}

		rcomp->Assign(1, std::move(c));
		r->Assign(4, std::move(rcomp));
		}
		break;

	case SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:
		{
		r->Assign(5, to_stringval(${ncv.netname_negotiate_context_id.net_name}));
		}
		break;

	default:
		break;
	}

	return r;
	}
%}

enum smb2_commands {
	SMB2_NEGOTIATE_PROTOCOL = 0,
	SMB2_SESSION_SETUP      = 1,
	SMB2_LOGOFF             = 2,
	SMB2_TREE_CONNECT       = 3,
	SMB2_TREE_DISCONNECT    = 4,
	SMB2_CREATE             = 5,
	SMB2_CLOSE              = 6,
	SMB2_FLUSH              = 7,
	SMB2_READ               = 8,
	SMB2_WRITE              = 9,
	SMB2_LOCK               = 10,
	SMB2_IOCTL              = 11,
	SMB2_CANCEL             = 12,
	SMB2_ECHO               = 13,
	SMB2_QUERY_DIRECTORY    = 14,
	SMB2_CHANGE_NOTIFY      = 15,
	SMB2_QUERY_INFO         = 16,
	SMB2_SET_INFO           = 17,
	SMB2_OPLOCK_BREAK       = 18,
};

enum smb2_share_types {
	SMB2_SHARE_TYPE_DISK = 0x01,
	SMB2_SHARE_TYPE_PIPE = 0x02,
	SMB2_SHARE_TYPE_PRINT = 0x03,
};

type SMB2_PDU(is_orig: bool) = record {
	header     : SMB2_Header(is_orig);
	message    : case $context.connection.is_error_response(header, is_orig) of {
		true  -> err : SMB2_error_response(header);
		false -> msg : SMB2_Message(header, is_orig);
	};
};

type SMB2_Message(header: SMB2_Header, is_orig: bool) = case is_orig of {
	true  -> request  : SMB2_Message_Request(header);
	false -> response : SMB2_Message_Response(header);
} &byteorder = littleendian;

type SMB2_Message_Request(header: SMB2_Header) = case header.command of {
	SMB2_NEGOTIATE_PROTOCOL -> negotiate_protocol  : SMB2_negotiate_request(header);
	SMB2_SESSION_SETUP      -> session_setup       : SMB2_session_setup_request(header);
	SMB2_TREE_CONNECT       -> tree_connect        : SMB2_tree_connect_request(header);
	SMB2_TREE_DISCONNECT    -> tree_disconnect     : SMB2_tree_disconnect_request(header);
	SMB2_CREATE             -> create              : SMB2_create_request(header);
	SMB2_CLOSE              -> close               : SMB2_close_request(header);
	SMB2_FLUSH              -> flush               : SMB2_flush_request(header);
	SMB2_READ               -> read                : SMB2_read_request(header);
	SMB2_WRITE              -> write               : SMB2_write_request(header);
	SMB2_LOCK               -> lock                : SMB2_lock_request(header);
	SMB2_IOCTL              -> ioctl               : SMB2_ioctl_request(header);
	SMB2_CANCEL             -> cancel              : SMB2_cancel_request(header);
	SMB2_ECHO               -> echo                : SMB2_echo_request(header);
	SMB2_QUERY_DIRECTORY    -> query_directory     : SMB2_query_directory_request(header);
	SMB2_CHANGE_NOTIFY      -> change_notify       : SMB2_change_notify_request(header);
	SMB2_QUERY_INFO         -> query_info          : SMB2_query_info_request(header);
	SMB2_SET_INFO           -> set_info            : SMB2_set_info_request(header);
	SMB2_OPLOCK_BREAK       -> oplock_break        : SMB2_oplock_break(header);

	default                 -> unknown_msg         : empty; # TODO: do something different here!
} &byteorder = littleendian;

type SMB2_Message_Response(header: SMB2_Header) = case header.command of {
	SMB2_NEGOTIATE_PROTOCOL -> negotiate_protocol  : SMB2_negotiate_response(header);
	SMB2_SESSION_SETUP      -> session_setup       : SMB2_session_setup_response(header);
	SMB2_TREE_CONNECT       -> tree_connect        : SMB2_tree_connect_response(header);
	SMB2_TREE_DISCONNECT    -> tree_disconnect     : SMB2_tree_disconnect_response(header);
	SMB2_CREATE             -> create              : SMB2_create_response(header);
	SMB2_CLOSE              -> close               : SMB2_close_response(header);
	SMB2_FLUSH              -> flush               : SMB2_flush_response(header);
	SMB2_READ               -> read                : SMB2_read_response(header);
	SMB2_WRITE              -> write               : SMB2_write_response(header);
	SMB2_LOCK               -> lock                : SMB2_lock_response(header);
	SMB2_IOCTL              -> ioctl               : SMB2_ioctl_response(header);
	SMB2_ECHO               -> echo                : SMB2_echo_response(header);
	SMB2_QUERY_DIRECTORY    -> query_directory     : SMB2_query_directory_response(header);
	SMB2_CHANGE_NOTIFY      -> change_notify       : SMB2_change_notify_response(header);
	SMB2_QUERY_INFO         -> query_info          : SMB2_query_info_response(header);
	SMB2_SET_INFO           -> set_info            : SMB2_set_info_response(header);
	SMB2_OPLOCK_BREAK       -> oplock_break        : SMB2_oplock_break(header);

	default                 -> unknown_msg         : empty; # TODO: do something different here!
} &byteorder=littleendian;

refine connection SMB_Conn += {

	%member{
		// Track tree_ids given in requests.  Sometimes the server doesn't
		// reply with the tree_id.  Index is message_id, yield is tree_id
		std::map<uint64,uint64> smb2_request_tree_id;
	%}

	function proc_smb2_message(h: SMB2_Header, is_orig: bool): bool
		%{
		if ( is_orig )
			{
			if ( zeek::BifConst::SMB::max_pending_messages > 0 &&
			     smb2_request_tree_id.size() >= zeek::BifConst::SMB::max_pending_messages )
				{
				if ( smb2_discarded_messages_state )
					zeek::BifEvent::enqueue_smb2_discarded_messages_state(zeek_analyzer(), zeek_analyzer()->Conn(),
					                                                     zeek::make_intrusive<zeek::StringVal>("tree"));

				smb2_request_tree_id.clear();
				}

			// Store the tree_id
			smb2_request_tree_id[${h.message_id}] = ${h.tree_id};
			}
		else
			{
			// Remove the stored tree_id unless the reply is pending.  It will
			// have already been used by the time this code is reached.
			if ( ${h.status} != 0x00000103 )
				{
				smb2_request_tree_id.erase(${h.message_id});
				}
			}

		if ( smb2_message )
			{
			zeek::BifEvent::enqueue_smb2_message(zeek_analyzer(), zeek_analyzer()->Conn(),
			                               BuildSMB2HeaderVal(h), is_orig);
			}
		return true;
		%}

	function get_request_tree_id(message_id: uint64): uint64
		%{
		// This is stored at the request and used at the reply.
		auto it = smb2_request_tree_id.find(message_id);

		if ( it == smb2_request_tree_id.end() )
			return 0;

		return it->second;
		%}

	function is_error_response(header: SMB2_Header, is_orig: bool): bool
		%{
		// In an request, we ignore this field. Relevant documentation is
		// at [MS-SMB2] 2.2.1.1 SMB2 Packet Header

		// For SMB 3.x, it's the ChannelSequence field, followed by
		// the reserved field. In older dialects, the client MUST set
		// it to 0, and the server MUST ignore it.

		// I don't believe that we care about the ChannelSequence,
		// since that seems inconsequential to our parsing.

		if ( is_orig )
			return false;

		// In a response, this is parsed as the status of the request.

		// Non-zero USUALLY means an error, except for the specific cases detailed in
		// [MS-SMB2] 3.3.4.4 Sending an Error Response

		auto status = static_cast<SMB_Status>(${header.status});

		switch ( status ) {
		case 0:
			// No error.
			return false;
		case STATUS_BUFFER_OVERFLOW:
			// SMB2_IOCTL is a bit loose, as it's only acceptable if the IOCTL
			// CtlCode is {FSCTL_PIPE_TRANSCEIVE, FSCTL_PIPE_PEEK, or
			// FSCTL_DFS_GETREFERRALS}, but we haven't parsed that yet.
			return ( ${header.command} != SMB2_IOCTL &&
			         ${header.command} != SMB2_QUERY_INFO &&
			         ${header.command} != SMB2_READ );
		case STATUS_INVALID_PARAMETER:
			// This is a bit loose, as it's only acceptable if the IOCTL
			// CtlCode is {FSCTL_SRV_COPYCHUNK or
			// FSCTL_SRV_COPYCHUNK_WRITE}, but we haven't parsed that yet.
			return ${header.command} != SMB2_IOCTL;
		case STATUS_MORE_PROCESSING_REQUIRED:
			// Return true (is_error) if it does NOT match this command
			return ${header.command} != SMB2_SESSION_SETUP;
		case STATUS_NOTIFY_ENUM_DIR:
			return ${header.command} != SMB2_CHANGE_NOTIFY;
		default:
			return true;
		}
		%}
};

type SMB2_file_attributes = record {
	flags : uint32;
} &let {
	read_only           : bool = ( flags & 0x00000001 ) > 0;
	hidden              : bool = ( flags & 0x00000002 ) > 0;
	system              : bool = ( flags & 0x00000004 ) > 0;
	directory           : bool = ( flags & 0x00000010 ) > 0;
	archive             : bool = ( flags & 0x00000020 ) > 0;
	normal              : bool = ( flags & 0x00000080 ) > 0;
	temporary           : bool = ( flags & 0x00000100 ) > 0;
	sparse_file         : bool = ( flags & 0x00000200 ) > 0;
	reparse_point       : bool = ( flags & 0x00000400 ) > 0;
	compressed          : bool = ( flags & 0x00000800 ) > 0;
	offline             : bool = ( flags & 0x00001000 ) > 0;
	not_content_indexed : bool = ( flags & 0x00002000 ) > 0;
	encrypted           : bool = ( flags & 0x00004000 ) > 0;
	integrity_stream    : bool = ( flags & 0x00008000 ) > 0;
	no_scrub_data       : bool = ( flags & 0x00020000 ) > 0;
};

type SMB2_Header(is_orig: bool) = record {
	head_length   : uint16;
	credit_charge : uint16;
	status        : uint32;
	command       : uint16;
	credits       : uint16;
	flags         : uint32;
	next_command  : uint32;
	message_id    : uint64;
	process_id    : uint32;
	tree_id       : uint32;
	session_id    : uint64;
	signature     : bytestring &length = 16;
} &let {
	response = (flags >> 24) & 1;
	async    = (flags >> 25) & 1;
	related  = (flags >> 26) & 1;
	msigned  = (flags >> 27) & 1;
	dfs      = (flags) & 1;
	request_tree_id = $context.connection.get_request_tree_id(message_id);
	is_pipe: bool = $context.connection.get_tree_is_pipe(is_orig ? tree_id : request_tree_id);
	proc : bool = $context.connection.proc_smb2_message(this, is_orig);
} &byteorder=littleendian;

# file ids and guids are the same thing and need unified somehow.
type SMB2_guid = record {
	persistent : uint64;
	_volatile   : uint64;
};


type SMB2_File_Notify_Information = record {
	next_entry_offset : uint32;
	action            : uint32;
	filename_len      : uint32;
	filename          : SMB2_string(filename_len);
};

type SMB2_symlink_error(byte_count: uint32) = record {
	sym_link_length   : uint32;
	sym_link_err_tag  : uint32;
	reparse_tag       : uint32;
	reparse_data_len  : uint16;
	unparsed_path_len : uint16;
	sub_name_offset   : uint16;
	sub_name_length   : uint16;
	print_name_offset : uint16;
	print_name_length : uint16;
	flags             : uint32;
	path_buffer       : bytestring &length = sub_name_length+print_name_length;
} &let {
	absolute_target_path  = (flags == 0x00000000);
	symlink_flag_relative = (flags == 0x00000001);
} &byteorder = littleendian;

type SMB2_error_data(header: SMB2_Header, byte_count: uint32) = case byte_count of {
	0                      -> empty:        empty;
	default                -> error:        SMB2_symlink_error(byte_count);
} &byteorder = littleendian;

type SMB2_error_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : padding[2];
	byte_count        : uint32;
	# This is implemented incorrectly and is disabled for now.
	#error_data        : SMB2_error_data(header, byte_count);
	stuff : bytestring &restofdata &transient;
} &byteorder = littleendian;

type SMB2_logoff_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_logoff_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_flush_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved1         : uint16;
	reserved2         : uint32;
	file_id           : SMB2_guid;
};

type SMB2_flush_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved1         : uint16;
};

type SMB2_cancel_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_echo_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_echo_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_query_directory_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	_class            : uint8;
	flags             : uint8;
	file_index        : uint32;
	file_id           : SMB2_guid;
	file_name_offset  : uint16;
	file_name_len     : uint16;
	output_buffer_len : uint32;
	pad               : padding to file_name_offset - header.head_length;
	file_name         : bytestring &length = file_name_len;
};

type SMB2_query_directory_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	buffer_offset     : uint16;
	buffer_len        : uint32;
	pad               : padding to buffer_offset - header.head_length;
	buffer            : bytestring &length = buffer_len;
};

type SMB2_change_notify_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	flags             : uint16;
	output_buffer_len : uint32;
	file_id           : SMB2_guid;
	completion_filter : uint32;
	reserved          : uint32;
};

type SMB2_change_notify_response(header: SMB2_Header) = record {
	structure_size       : uint16;
	output_buffer_offset : uint16;
	output_buffer_len    : uint32;
	pad                  : padding to output_buffer_offset - header.head_length;
	buffer               : SMB2_File_Notify_Information[] &length = output_buffer_len;
};

type SMB2_query_info_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	info_type           : uint8;
	file_info_class     : uint8;
	output_buffer_len   : uint32;
	input_buffer_offset : uint16;
	reserved            : uint16;
	input_buffer_len    : uint32;
	additional_info     : uint32;
	flags               : uint32;
	file_id             : SMB2_guid;
	pad                 : padding to input_buffer_offset - header.head_length;
	buffer              : bytestring &length = input_buffer_len;
};

type SMB2_query_info_response(header: SMB2_Header) = record {
	structure_size      : uint16;
	buffer_offset       : uint16;
	buffer_len          : uint32;
	pad                 : padding to buffer_offset - header.head_length;
	# TODO: a new structure needs to be created for this.
	buffer              : bytestring &length = buffer_len;
};

type SMB2_oplock_break(header: SMB2_Header) = record {
	structure_size      : uint16;
	oplock_level        : uint8;
	reserved            : uint8;
	reserved2           : uint32;
	file_id             : SMB2_guid;
};
