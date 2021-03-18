enum smb2_set_info_type {
	SMB2_0_INFO_FILE       = 0x01,
	SMB2_0_INFO_FILESYSTEM = 0x02,
	SMB2_0_INFO_SECURITY   = 0x03,
	SMB2_0_INFO_QUOTA      = 0x04,
};

# taken from MS-FSCC 2.4 and 2.5
enum smb_file_info_type {
	SMB2_FILE_BASIC_INFO           = 0x04,
	SMB2_FILE_RENAME_INFO          = 0x0a,
	SMB2_FILE_DISPOSITION_INFO     = 0x0d,
	SMB2_FILE_ALLOCATION_INFO      = 0x13,
	SMB2_FILE_ENDOFFILE_INFO       = 0x14,
	SMB2_FILE_FULLEA_INFO          = 0x0f,
	SMB2_FILE_LINK_INFO            = 0x0b,
	SMB2_FILE_MODE_INFO            = 0x10,
	SMB2_FILE_PIPE_INFO            = 0x18,
	SMB2_FILE_POSITION_INFO        = 0x0e,
	SMB2_FILE_SHORTNAME_INFO       = 0x28,
	SMB2_FILE_VALIDDATALENGTH_INFO = 0x27,
	SMB2_FILE_FSCONTROL_INFO       = 0x06,
	SMB2_FILE_FSOBJECTID_INFO      = 0x08,
}

refine connection SMB_Conn += {

	function proc_smb2_set_info_request_file(val: SMB2_file_basic_info): bool
		%{
		if ( smb2_file_sattr )
			zeek::BifEvent::enqueue_smb2_file_sattr(zeek_analyzer(),
			                                  zeek_analyzer()->Conn(),
			                                  BuildSMB2HeaderVal(${val.sir.header}),
			                                  BuildSMB2GUID(${val.sir.file_id}),
			                                  SMB_BuildMACTimes(${val.last_write_time},
			                                                    ${val.last_access_time},
			                                                    ${val.creation_time},
			                                                    ${val.change_time}),
			                                  smb2_file_attrs_to_zeek(${val.file_attrs}));

		return true;
		%}

	function proc_smb2_set_info_request_file_rename(val: SMB2_file_rename_info): bool
		%{
		if ( smb2_file_rename )
			zeek::BifEvent::enqueue_smb2_file_rename(zeek_analyzer(),
			                                   zeek_analyzer()->Conn(),
			                                   BuildSMB2HeaderVal(${val.sir.header}),
			                                   BuildSMB2GUID(${val.sir.file_id}),
			                                   smb2_string2stringval(${val.filename}));

		return true;
		%}

	function proc_smb2_set_info_request_file_delete(val: SMB2_file_disposition_info): bool
		%{
		if ( smb2_file_delete )
			zeek::BifEvent::enqueue_smb2_file_delete(zeek_analyzer(),
			                                   zeek_analyzer()->Conn(),
			                                   BuildSMB2HeaderVal(${val.sir.header}),
			                                   BuildSMB2GUID(${val.sir.file_id}),
			                                   (${val.delete_pending} > 0));

		return true;
		%}

	function proc_smb2_set_info_request_file_allocation(val: SMB2_file_allocation_info): bool
		%{
		if ( smb2_file_allocation )
			zeek::BifEvent::enqueue_smb2_file_allocation(zeek_analyzer(),
			                                       zeek_analyzer()->Conn(),
			                                       BuildSMB2HeaderVal(${val.sir.header}),
			                                       BuildSMB2GUID(${val.sir.file_id}),
			                                       (${val.allocation_size}));

		return true;
		%}

	function proc_smb2_set_info_request_file_endoffile(val: SMB2_file_endoffile_info): bool
		%{
		if ( smb2_file_endoffile )
			zeek::BifEvent::enqueue_smb2_file_endoffile(zeek_analyzer(),
			                                      zeek_analyzer()->Conn(),
			                                      BuildSMB2HeaderVal(${val.sir.header}),
			                                      BuildSMB2GUID(${val.sir.file_id}),
			                                      ${val.endoffile});

		return true;
		%}

	function proc_smb2_set_info_request_file_fullea(val: SMB2_file_fullea_info): bool
		%{
		if ( smb2_file_fullea )
			{
			auto eas = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::SMB2::FileEAs);

			for ( auto i = 0u; i < ${val.ea_vector}->size(); ++i )
				{
				auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::FileEA);
				r->Assign(0, smb2_string2stringval(${val.ea_vector[i].ea_name}));
				r->Assign(1, smb2_string2stringval(${val.ea_vector[i].ea_value}));

				eas->Assign(i, std::move(r));
				}

			zeek::BifEvent::enqueue_smb2_file_fullea(zeek_analyzer(),
			                                   zeek_analyzer()->Conn(),
			                                   BuildSMB2HeaderVal(${val.sir.header}),
			                                   BuildSMB2GUID(${val.sir.file_id}),
			                                   std::move(eas));
			}

		return true;
		%}

	function proc_smb2_set_info_request_file_link(val: SMB2_file_link_info): bool
		%{
		if ( smb2_file_link )
			zeek::BifEvent::enqueue_smb2_file_link(zeek_analyzer(),
			                                 zeek_analyzer()->Conn(),
			                                 BuildSMB2HeaderVal(${val.sir.header}),
			                                 BuildSMB2GUID(${val.sir.file_id}),
			                                 ${val.root_directory},
			                                 smb2_string2stringval(${val.file_name}));

		return true;
		%}

	function proc_smb2_set_info_request_file_mode(val: SMB2_file_mode_info): bool
		%{
		if ( smb2_file_mode )
			zeek::BifEvent::enqueue_smb2_file_mode(zeek_analyzer(),
			                                 zeek_analyzer()->Conn(),
			                                 BuildSMB2HeaderVal(${val.sir.header}),
			                                 BuildSMB2GUID(${val.sir.file_id}),
			                                 ${val.mode});

		return true;
		%}

	function proc_smb2_set_info_request_file_pipe(val: SMB2_file_pipe_info): bool
		%{
		if ( smb2_file_pipe )
			zeek::BifEvent::enqueue_smb2_file_pipe(zeek_analyzer(),
			                                 zeek_analyzer()->Conn(),
			                                 BuildSMB2HeaderVal(${val.sir.header}),
			                                 BuildSMB2GUID(${val.sir.file_id}),
			                                 ${val.read_mode},
			                                 ${val.completion_mode});

		return true;
		%}

	function proc_smb2_set_info_request_file_position(val: SMB2_file_position_info): bool
		%{
		if ( smb2_file_position )
			zeek::BifEvent::enqueue_smb2_file_position(zeek_analyzer(),
			                                     zeek_analyzer()->Conn(),
			                                     BuildSMB2HeaderVal(${val.sir.header}),
			                                     BuildSMB2GUID(${val.sir.file_id}),
			                                     ${val.current_byte_offset});

		return true;
		%}

	function proc_smb2_set_info_request_file_shortname(val: SMB2_file_shortname_info): bool
		%{
		if ( smb2_file_shortname )
			zeek::BifEvent::enqueue_smb2_file_shortname(zeek_analyzer(),
			                                      zeek_analyzer()->Conn(),
			                                      BuildSMB2HeaderVal(${val.sir.header}),
			                                      BuildSMB2GUID(${val.sir.file_id}),
			                                      smb2_string2stringval(${val.filename}));

		return true;
		%}

	function proc_smb2_set_info_request_file_validdatalength(val: SMB2_file_validdatalength_info): bool
		%{
		if ( smb2_file_validdatalength )
			zeek::BifEvent::enqueue_smb2_file_validdatalength(zeek_analyzer(),
			                                            zeek_analyzer()->Conn(),
			                                            BuildSMB2HeaderVal(${val.sir.header}),
			                                            BuildSMB2GUID(${val.sir.file_id}),
			                                            ${val.validdatalength});

		return true;
		%}

	function proc_smb2_set_info_request_file_fscontrol(val: SMB2_file_fscontrol_info): bool
		%{
		if ( smb2_file_fscontrol )
			{
			auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::Fscontrol);
			r->Assign(0, static_cast<int>(${val.free_space_start_filtering}));
			r->Assign(1, static_cast<int>(${val.free_space_start_threshold}));
			r->Assign(2, static_cast<int>(${val.free_space_stop_filtering}));
			r->Assign(3, ${val.default_quota_threshold});
			r->Assign(4, ${val.default_quota_limit});
			r->Assign(5, ${val.file_system_control_flags});

			zeek::BifEvent::enqueue_smb2_file_fscontrol(zeek_analyzer(),
			                                      zeek_analyzer()->Conn(),
			                                      BuildSMB2HeaderVal(${val.sir.header}),
			                                      BuildSMB2GUID(${val.sir.file_id}),
			                                      std::move(r));
			}

		return true;
		%}

	function proc_smb2_set_info_request_file_fsobjectid(val: SMB2_file_fsobjectid_info): bool
		%{
		if ( smb2_file_fsobjectid )
			zeek::BifEvent::enqueue_smb2_file_fsobjectid(zeek_analyzer(),
			                                       zeek_analyzer()->Conn(),
			                                       BuildSMB2HeaderVal(${val.sir.header}),
			                                       BuildSMB2GUID(${val.sir.file_id}),
			                                       BuildSMB2GUID(${val.object_id}),
			                                       smb2_string2stringval(${val.extended_info}));

		return true;
		%}
}


type SMB2_file_basic_info(sir: SMB2_set_info_request) = record {
	creation_time    : SMB_timestamp;
	last_access_time : SMB_timestamp;
	last_write_time  : SMB_timestamp;
	change_time      : SMB_timestamp;
	file_attrs       : SMB2_file_attributes;
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file(this);
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

type SMB2_file_allocation_info(sir: SMB2_set_info_request) = record {
	allocation_size : int64;
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_allocation(this);
};

type SMB2_file_endoffile_info(sir: SMB2_set_info_request) = record {
	endoffile : int64;
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_endoffile(this);
};

type SMB2_file_fullea_info_element = record {
	next_entry_offset : uint32;
	flags             : uint8;
	ea_name_length    : uint8;
	ea_value_length   : uint16;
	ea_name           : SMB2_string(ea_name_length);
	ea_value          : SMB2_string(ea_value_length);
	pad_to_next       : padding to next_entry_offset;
} &let {
	next_offset: int = next_entry_offset;
};

type SMB2_file_fullea_info(sir: SMB2_set_info_request) = record {
	ea_vector : SMB2_file_fullea_info_element[] &until($element.next_offset == 0);
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_fullea(this);
};

type SMB2_file_link_info(sir: SMB2_set_info_request) = record {
	replace_if_exists : uint8;
	reserved          : uint8[7];
	root_directory    : uint64;
	file_name_length  : uint32;
	file_name         : SMB2_string(file_name_length);
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_link(this);
};

type SMB2_file_mode_info(sir: SMB2_set_info_request) = record {
	mode : uint32;
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_mode(this);
};

type SMB2_file_pipe_info(sir: SMB2_set_info_request) = record {
	read_mode       : uint32;
	completion_mode : uint32;
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_pipe(this);
};

type SMB2_file_position_info(sir: SMB2_set_info_request) = record {
	current_byte_offset : int64;
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_position(this);
};

type SMB2_file_shortname_info(sir: SMB2_set_info_request) = record {
	filename_length : uint32;
	filename        : SMB2_string(filename_length);
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_shortname(this);
};

type SMB2_file_validdatalength_info(sir: SMB2_set_info_request) = record {
	validdatalength : int64;
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_validdatalength(this);
};

type SMB2_file_fscontrol_info(sir: SMB2_set_info_request) = record {
	free_space_start_filtering  : int64;
	free_space_start_threshold  : int64;
	free_space_stop_filtering   : int64;
	default_quota_threshold     : uint64;
	default_quota_limit         : uint64;
	file_system_control_flags   : uint32;
	pad                         : padding[4];
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_fscontrol(this);
};

type SMB2_file_fsobjectid_info(sir: SMB2_set_info_request) = record {
	object_id     : SMB2_guid;
	extended_info : SMB2_string(48);
} &let {
	proc: bool = $context.connection.proc_smb2_set_info_request_file_fsobjectid(this);
};

type SMB2_set_info_file_class(sir: SMB2_set_info_request) = case sir.info_level of {
	SMB2_FILE_BASIC_INFO           -> file_basic           : SMB2_file_basic_info(sir);
	SMB2_FILE_RENAME_INFO          -> file_rename          : SMB2_file_rename_info(sir);
	SMB2_FILE_DISPOSITION_INFO     -> file_disposition     : SMB2_file_disposition_info(sir);
	SMB2_FILE_ALLOCATION_INFO      -> file_allocation      : SMB2_file_allocation_info(sir);
	SMB2_FILE_ENDOFFILE_INFO       -> file_endoffile       : SMB2_file_endoffile_info(sir);
	SMB2_FILE_FULLEA_INFO          -> file_fullea          : SMB2_file_fullea_info(sir);
	SMB2_FILE_LINK_INFO            -> file_link            : SMB2_file_link_info(sir);
	SMB2_FILE_MODE_INFO            -> file_mode            : SMB2_file_mode_info(sir);
	SMB2_FILE_PIPE_INFO            -> file_pipe            : SMB2_file_pipe_info(sir);
	SMB2_FILE_POSITION_INFO        -> file_position        : SMB2_file_position_info(sir);
	SMB2_FILE_SHORTNAME_INFO       -> file_shortname       : SMB2_file_shortname_info(sir);
	SMB2_FILE_VALIDDATALENGTH_INFO -> file_validdatalength : SMB2_file_validdatalength_info(sir);
	default                        -> info_file_unhandled  : empty;
};

type SMB2_set_info_filesystem_class(sir: SMB2_set_info_request) = case sir.info_level of {
	SMB2_FILE_FSCONTROL_INFO   -> file_fscontrol      : SMB2_file_fscontrol_info(sir);
	SMB2_FILE_FSOBJECTID_INFO  -> file_fsobjectid     : SMB2_file_fsobjectid_info(sir);
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
		SMB2_0_INFO_FILE        -> file_info       : SMB2_set_info_file_class(this);
		SMB2_0_INFO_FILESYSTEM  -> filesystem_info : SMB2_set_info_filesystem_class(this);
		# TODO: SMB2_0_INFO_SECURITY, SMB2_0_INFO_QUOTA
		default                 -> class_unhandled : empty;
	};
};

type SMB2_set_info_response(header: SMB2_Header) = record {
	structure_size      : uint16;
};
