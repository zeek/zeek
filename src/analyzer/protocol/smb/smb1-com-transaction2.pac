enum Trans2_subcommands {
	TRANS2_OPEN2 = 0x0000,
	TRANS2_FIND_FIRST2 = 0x0001,
	TRANS2_FIND_NEXT2 = 0x0002,
	TRANS2_QUERY_FS_INFORMATION = 0x0003,
	TRANS2_SET_FS_INFORMATION = 0x0004,
	TRANS2_QUERY_PATH_INFORMATION = 0x0005,
	TRANS2_SET_PATH_INFORMATION = 0x0006,
	TRANS2_QUERY_FILE_INFORMATION = 0x0007,
	TRANS2_SET_FILE_INFORMATION = 0x0008,
	TRANS2_FSCTL = 0x0009,
	TRANS2_IOCTL2 = 0x000a,
	TRANS2_FIND_NOTIFY_FIRST = 0x000b,
	TRANS2_FIND_NOTIFY_NEXT = 0x000c,
	TRANS2_CREATE_DIRECTORY = 0x000d,
	TRANS2_SESSION_SETUP = 0x000e,
	TRANS2_GET_DFS_REFERRAL = 0x0010,
	TRANS2_REPORT_DFS_INCONSISTENCY = 0x0011,
};

refine connection SMB_Conn += {

	function proc_smb1_transaction2_request(header: SMB_Header, val: SMB1_transaction2_request): bool
		%{
		if ( smb1_transaction2_request )
			{
			auto args = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB1::Trans2_Args);
			args->Assign(0, ${val.total_param_count});
			args->Assign(1, ${val.total_data_count});
			args->Assign(2, ${val.max_param_count});
			args->Assign(3, ${val.max_data_count});
			args->Assign(4, ${val.max_setup_count});
			args->Assign(5, ${val.flags});
			args->Assign(6, ${val.timeout});
			args->Assign(7, ${val.param_count});
			args->Assign(8, ${val.param_offset});
			args->Assign(9, ${val.data_count});
			args->Assign(10, ${val.data_offset});
			args->Assign(11, ${val.setup_count});

			zeek::BifEvent::enqueue_smb1_transaction2_request(zeek_analyzer(),
			                                            zeek_analyzer()->Conn(),
			                                            SMBHeaderVal(header),
			                                            std::move(args),
			                                            ${val.sub_cmd});
			}

		return true;
		%}

	function proc_smb1_transaction2_response(header: SMB_Header, val: SMB1_transaction2_response): bool
		%{
		//if ( smb1_transaction2_response )
		//	zeek::BifEvent::enqueue_smb1_transaction2_response(zeek_analyzer(), zeek_analyzer()->Conn(), SMBHeaderVal(header), ${val.sub_cmd});
		return true;
		%}

};

type SMB1_transaction2_request(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	max_param_count     : uint16;
	max_data_count      : uint16;
	max_setup_count     : uint8;
	reserved1           : uint8;
	flags               : uint16;
	timeout             : uint32;
	reserved2           : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	setup_count         : uint8;
	reserved3           : uint8;

	# I suspect this needs a word_count check
	#setup               : uint16[setup_count];
	sub_cmd              : uint16;

	byte_count          : uint16;
	#stuff               : bytestring &length=byte_count;
	pad1                : padding to (param_offset - SMB_Header_length);
	parameters : case sub_cmd of {
		TRANS2_FIND_FIRST2            -> find_first2      : trans2_find_first2_request(header);
		TRANS2_QUERY_FS_INFORMATION   -> query_fs_info    : trans2_query_fs_info_request(header);
		TRANS2_QUERY_PATH_INFORMATION -> query_path_info  : trans2_query_path_info_request(header);
		TRANS2_QUERY_FILE_INFORMATION -> query_file_info  : trans2_query_file_info_request(header);
		TRANS2_SET_FILE_INFORMATION   -> set_file_info    : trans2_set_file_info_request(header);
		TRANS2_GET_DFS_REFERRAL       -> get_dfs_referral : trans2_get_dfs_referral_request(header);
		default -> blah : bytestring &restofdata &transient;
	};
	#pad2                : padding to (data_offset - SMB_Header_length);
	#data                : bytestring &length=data_count;
} &let {
	proc : bool = $context.connection.proc_smb1_transaction2_request(header, this);
};

type SMB1_transaction2_response(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	reserved1           : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	param_displacement  : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	data_displacement   : uint16;
	setup_count         : uint8;
	reserved2           : uint8;
	#setup               : uint16[setup_count];

	byte_count          : uint16;
	stuff               : bytestring &length=byte_count;

	#pad1                : padding to (param_offset - SMB_Header_length);
	#parameters          : bytestring &length = byte_count;
	#pad2                : padding to (data_offset - SMB_Header_length);
	#data                : bytestring &length = data_count; # TODO: make SMB1_transaction2_data structure -- SMB1_transaction_data(header, data_count, 0, SMB_UNKNOWN);
} &let {
	proc : bool = $context.connection.proc_smb1_transaction2_response(header, this);
};

###########################################

refine connection SMB_Conn += {

	function proc_trans2_find_first2_request(header: SMB_Header, val: trans2_find_first2_request): bool
		%{
		if ( smb1_trans2_find_first2_request )
			{
			auto result = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB1::Find_First2_Request_Args);
			result->Assign(0, ${val.search_attrs});
			result->Assign(1, ${val.search_count});
			result->Assign(2, ${val.flags});
			result->Assign(3, ${val.info_level});
			result->Assign(4, ${val.search_storage_type});
			result->Assign(5, smb_string2stringval(${val.file_name}));
			zeek::BifEvent::enqueue_smb1_trans2_find_first2_request(zeek_analyzer(),
			                                                        zeek_analyzer()->Conn(),
			                                                        SMBHeaderVal(header),
			                                                        std::move(result));

			}
		return true;
		%}

	function proc_trans2_find_first2_response(header: SMB_Header, val: trans2_find_first2_response): bool
		%{
		// TODO: implement this.
		//printf("trans2_find_first2 response!\n");
		return true;
		%}

};

type trans2_find_first2_request(header: SMB_Header) = record {
	search_attrs        : uint16;
	search_count        : uint16;
	flags               : uint16;
	info_level          : uint16;
	search_storage_type : uint32;
	file_name           : SMB_string(header.unicode, offsetof(file_name));
} &let {
	proc : bool = $context.connection.proc_trans2_find_first2_request(header, this);
};

type trans2_find_first2_response(header: SMB_Header) = record {
	sid : uint16;
	search_count : uint16;
	end_of_search : uint16;
	ea_error_offset : uint16;
	last_name_offset : uint16;
} &let {
	proc : bool = $context.connection.proc_trans2_find_first2_response(header, this);
};

###########################################

refine connection SMB_Conn += {

	function proc_trans2_query_fs_info_request(header: SMB_Header, val: trans2_query_fs_info_request): bool
		%{
		// TODO: implement this.
		//printf("trans2_query_fs_info request!\n");
		return true;
		%}

	function proc_trans2_query_fs_info_response(header: SMB_Header, val: trans2_query_fs_info_response): bool
		%{
		// TODO: implement this.
		//printf("trans2_query_fs_info response!\n");
		return true;
		%}

};

type trans2_query_fs_info_request(header: SMB_Header) = record {
	# TODO: implement this.
} &let {
	proc : bool = $context.connection.proc_trans2_query_fs_info_request(header, this);
};

type trans2_query_fs_info_response(header: SMB_Header) = record {
	# TODO: implement this.
} &let {
	proc : bool = $context.connection.proc_trans2_query_fs_info_response(header, this);
};

###########################################

refine connection SMB_Conn += {

	function proc_trans2_query_path_info_request(header: SMB_Header, val: trans2_query_path_info_request): bool
		%{
		if ( smb1_trans2_query_path_info_request )
			{
			zeek::BifEvent::enqueue_smb1_trans2_query_path_info_request(zeek_analyzer(),
			                                                      zeek_analyzer()->Conn(),
			                                                      SMBHeaderVal(header),
			                                                      smb_string2stringval(${val.file_name}));
			}
		return true;
		%}

	function proc_trans2_query_path_info_response(header: SMB_Header, val: trans2_query_path_info_response): bool
		%{
		// TODO: implement this.
		//printf("trans2_query_path_info response!\n");
		return true;
		%}

};

type trans2_query_path_info_request(header: SMB_Header) = record {
	information_level : uint16;
	reserved          : uint32;
	file_name         : SMB_string(header.unicode, offsetof(file_name));
} &let {
	proc : bool = $context.connection.proc_trans2_query_path_info_request(header, this);
};

type trans2_query_path_info_response(header: SMB_Header) = record {
	# TODO: implement this.
} &let {
	proc : bool = $context.connection.proc_trans2_query_path_info_response(header, this);
};

###########################################

refine connection SMB_Conn += {

	function proc_trans2_query_file_info_request(header: SMB_Header, val: trans2_query_file_info_request): bool
		%{
		// TODO: implement this.
		//printf("trans2_query_file_info request!\n");
		return true;
		%}

	function proc_trans2_query_file_info_response(header: SMB_Header, val: trans2_query_file_info_response): bool
		%{
		// TODO: implement this.
		//printf("trans2_query_file_info response!\n");
		return true;
		%}

};

type trans2_query_file_info_request(header: SMB_Header) = record {
	file_id           : uint16;
	information_level : uint16;
} &let {
	proc : bool = $context.connection.proc_trans2_query_file_info_request(header, this);
};

type trans2_query_file_info_response(header: SMB_Header) = record {
	# TODO: implement this.
} &let {
	proc : bool = $context.connection.proc_trans2_query_file_info_response(header, this);
};

###########################################

refine connection SMB_Conn += {

	function proc_trans2_set_file_info_request(header: SMB_Header, val: trans2_set_file_info_request): bool
		%{
		// TODO: implement this.
		//printf("trans2_set_file_info request!\n");
		return true;
		%}

	function proc_trans2_set_file_info_response(header: SMB_Header, val: trans2_set_file_info_response): bool
		%{
		// TODO: implement this.
		//printf("trans2_set_file_info response!\n");
		return true;
		%}

};

type trans2_set_file_info_request(header: SMB_Header) = record {
	# TODO: implement this.
} &let {
	proc : bool = $context.connection.proc_trans2_set_file_info_request(header, this);
};

type trans2_set_file_info_response(header: SMB_Header) = record {
	# TODO: implement this.
} &let {
	proc : bool = $context.connection.proc_trans2_set_file_info_response(header, this);
};

###########################################

refine connection SMB_Conn += {

	function proc_trans2_get_dfs_referral_request(header: SMB_Header, val: trans2_get_dfs_referral_request): bool
		%{
		if ( smb1_trans2_get_dfs_referral_request )
			{
			zeek::BifEvent::enqueue_smb1_trans2_get_dfs_referral_request(zeek_analyzer(),
			                                                       zeek_analyzer()->Conn(),
			                                                       SMBHeaderVal(header),
			                                                       smb_string2stringval(${val.file_name}));
			}
		return true;
		%}

	function proc_trans2_get_dfs_referral_response(header: SMB_Header, val: trans2_get_dfs_referral_response): bool
		%{
		// TODO: implement this.
		//printf("trans2_get_dfs_referral response!\n");
		return true;
		%}

};

type trans2_get_dfs_referral_request(header: SMB_Header) = record {
	max_referral_level  : uint16;
	file_name           : SMB_string(header.unicode, offsetof(file_name));
} &let {
	proc : bool = $context.connection.proc_trans2_get_dfs_referral_request(header, this);
};

type trans2_get_dfs_referral_response(header: SMB_Header) = record {
	# TODO: implement this.
} &let {
	proc : bool = $context.connection.proc_trans2_get_dfs_referral_response(header, this);
};

###########################################
