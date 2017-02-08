enum smb2_set_info_type {
	SMB2_0_INFO_FILE       = 0x01,
	SMB2_0_INFO_FILESYSTEM = 0x02,
	SMB2_0_INFO_SECURITY   = 0x03,
	SMB2_0_INFO_QUOTA      = 0x04,
};

enum smb_file_info_type {
	SMB2_FILE_RENAME_INFO       = 0x0a,
	SMB2_FILE_DISPOSITION_INFO = 0x0d,
}

refine connection SMB_Conn += {

	function proc_smb2_set_info_request_file_rename(val: SMB2_file_rename_info): bool
		%{
		if ( smb2_file_rename )
			BifEvent::generate_smb2_file_rename(bro_analyzer(),
			                                    bro_analyzer()->Conn(),
			                                    BuildSMB2HeaderVal(${val.sir.header}),
			                                    BuildSMB2GUID(${val.sir.file_id}),
			                                    smb2_string2stringval(${val.filename}));

		return true;
		%}

	function proc_smb2_set_info_request_file_delete(val: SMB2_file_disposition_info): bool
		%{
		if ( smb2_file_delete )
			BifEvent::generate_smb2_file_delete(bro_analyzer(),
			                                    bro_analyzer()->Conn(),
			                                    BuildSMB2HeaderVal(${val.sir.header}),
			                                    BuildSMB2GUID(${val.sir.file_id}),
			                                    (${val.delete_pending} > 0));

		return true;
		%}

};

type SMB2_file_rename_info(sir: SMB2_set_info_request) = record {
	replace_if_exists : uint8;
	reserved          : uint8[7];
	root_directory    : uint64;
	filename_len      : uint32;
	filename          : SMB2_string(filename_len);
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_rename(this);
};

type SMB2_file_disposition_info(sir: SMB2_set_info_request) = record {
	delete_pending : uint8;
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_delete(this);
};

type SMB2_set_info_file_class(sir: SMB2_set_info_request) = case sir.info_level of {
	SMB2_FILE_RENAME_INFO      -> file_rename         : SMB2_file_rename_info(sir);
	SMB2_FILE_DISPOSITION_INFO -> file_disposition    : SMB2_file_disposition_info(sir);
	default                    -> info_file_unhandled : empty;
};

type SMB2_set_info_request(header: SMB2_Header) = record {
	structure_size  : uint16;
	info_class      : uint8;
	info_level      : uint8;
	buffer_len      : uint32;
	buffer_offset   : uint16;
	reserved        : uint16;
	additional_info : uint32;
	file_id         : SMB2_guid;

	pad             : padding to buffer_offset - header.head_length;
	data            : case info_class of {
		SMB2_0_INFO_FILE -> file_info       : SMB2_set_info_file_class(this);
		default          -> class_unhandled : empty;
	};
};

type SMB2_set_info_response(header: SMB2_Header) = record {
	structure_size      : uint16;
};
