# Documentation for SMB2 protocol from here:
#     http://msdn.microsoft.com/en-us/library/cc246497(v=PROT.13).aspx

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
	message    : case header.status of {
		# Status 0 indicates success.  In the case of a
		# request this should just happen to work out due to
		# how the fields are set.
		0                               -> msg                      : SMB2_Message(header, is_orig);
		STATUS_BUFFER_OVERFLOW          -> buffer_overflow          : SMB2_Message(header, is_orig);
		STATUS_MORE_PROCESSING_REQUIRED -> more_processing_required : SMB2_Message(header, is_orig);
		default                         -> err                      : SMB2_error_response(header);
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

	function BuildSMB2HeaderVal(hdr: SMB2_Header): BroVal
		%{
		RecordVal* r = new RecordVal(BifType::Record::SMB2::Header);

		r->Assign(0, new Val(${hdr.credit_charge}, TYPE_COUNT));
		r->Assign(1, new Val(${hdr.status}, TYPE_COUNT));
		r->Assign(2, new Val(${hdr.command}, TYPE_COUNT));
		r->Assign(3, new Val(${hdr.credits}, TYPE_COUNT));
		r->Assign(4, new Val(${hdr.flags}, TYPE_COUNT));
		r->Assign(5, new Val(${hdr.message_id}, TYPE_COUNT));
		r->Assign(6, new Val(${hdr.process_id}, TYPE_COUNT));
		r->Assign(7, new Val(${hdr.tree_id}, TYPE_COUNT));
		r->Assign(8, new Val(${hdr.session_id}, TYPE_COUNT));
		r->Assign(9, bytestring_to_val(${hdr.signature}));

		return r;
		%}

	function BuildSMB2GUID(file_id: SMB2_guid): BroVal
		%{
		RecordVal* r = new RecordVal(BifType::Record::SMB2::GUID);

		r->Assign(0, new Val(${file_id.persistent}, TYPE_COUNT));
		r->Assign(1, new Val(${file_id._volatile}, TYPE_COUNT));

		return r;
		%}

	function proc_smb2_message(h: SMB2_Header, is_orig: bool): bool
		%{
		//if ( ${h.command} == SMB2_READ )
		//	printf("got a read %s command\n", is_orig ? "request" : "response");

		if ( smb2_message )
			{
			BifEvent::generate_smb2_message(bro_analyzer(), bro_analyzer()->Conn(),
			                                BuildSMB2HeaderVal(h),
			                                is_orig);
			}
		return true;
		%}
};

function smb2_file_attrs_to_bro(val: SMB2_file_attributes): BroVal
	%{
	RecordVal* r = new RecordVal(BifType::Record::SMB2::FileAttrs);

	r->Assign(0, new Val(${val.read_only}, TYPE_BOOL));
	r->Assign(1, new Val(${val.hidden}, TYPE_BOOL));
	r->Assign(2, new Val(${val.system}, TYPE_BOOL));
	r->Assign(3, new Val(${val.directory}, TYPE_BOOL));
	r->Assign(4, new Val(${val.archive}, TYPE_BOOL));
	r->Assign(5, new Val(${val.normal}, TYPE_BOOL));
	r->Assign(6, new Val(${val.temporary}, TYPE_BOOL));
	r->Assign(7, new Val(${val.sparse_file}, TYPE_BOOL));
	r->Assign(8, new Val(${val.reparse_point}, TYPE_BOOL));
	r->Assign(9, new Val(${val.compressed}, TYPE_BOOL));
	r->Assign(10, new Val(${val.offline}, TYPE_BOOL));
	r->Assign(11, new Val(${val.not_content_indexed}, TYPE_BOOL));
	r->Assign(12, new Val(${val.encrypted}, TYPE_BOOL));
	r->Assign(13, new Val(${val.integrity_stream}, TYPE_BOOL));
	r->Assign(14, new Val(${val.no_scrub_data}, TYPE_BOOL));

	return r;
	%}

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
	is_pipe: bool = $context.connection.get_tree_is_pipe(tree_id);
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
