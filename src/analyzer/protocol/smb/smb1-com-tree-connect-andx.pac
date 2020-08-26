refine connection SMB_Conn += {

	function proc_smb1_tree_connect_andx_request(header: SMB_Header, val: SMB1_tree_connect_andx_request): bool
		%{
		if ( smb1_tree_connect_andx_request )
			zeek::BifEvent::enqueue_smb1_tree_connect_andx_request(zeek_analyzer(),
			                                                 zeek_analyzer()->Conn(),
			                                                 SMBHeaderVal(header),
			                                                 smb_string2stringval(${val.path}),
			                                                 smb_string2stringval(${val.service}));
		return true;
		%}

	function proc_smb1_tree_connect_andx_response(header: SMB_Header, val: SMB1_tree_connect_andx_response): bool
		%{
		auto service_string = smb_string2stringval(${val.service});
		auto s = reinterpret_cast<const char*>(service_string->Bytes());

		if ( strncmp(s, "IPC", 3) == 0 )
			set_tree_is_pipe(${header.tid});

		if ( smb1_tree_connect_andx_response )
			zeek::BifEvent::enqueue_smb1_tree_connect_andx_response(zeek_analyzer(),
			                                                  zeek_analyzer()->Conn(),
			                                                  SMBHeaderVal(header),
			                                                  std::move(service_string),
			                                                  ${val.byte_count} > ${val.service.a}->size() ?
			                                                     smb_string2stringval(${val.native_file_system[0]}) :
			                                                     zeek::val_mgr->EmptyString());

		return true;
		%}

};

type SMB1_tree_connect_andx_request(header: SMB_Header, offset: uint16) = record {
	word_count      : uint8;
	andx            : SMB_andx;
	flags           : uint16;
	password_length : uint16;

	byte_count      : uint16;
	password        : uint8[password_length];
	path            : SMB_string(header.unicode, offsetof(path));
	service         : SMB_string(false, offsetof(service));

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command    : SMB_andx_command(header, true, offset+offsetof(andx_command), andx.command);
} &let {
	proc : bool = $context.connection.proc_smb1_tree_connect_andx_request(header, this);
};

type SMB1_tree_connect_andx_response(header: SMB_Header, offset: uint16) = record {
	word_count         : uint8;
	andx               : SMB_andx;
	optional_support   : uint16[word_count<3 ? 0 : 1];
	pad                : padding[word_count<3 ? 0 : (word_count-3)*2];

	byte_count         : uint16;
	service            : SMB_string(false, offsetof(service));
	native_file_system : SMB_string(header.unicode, offsetof(native_file_system))[byte_count > sizeof(service) ? 1 : 0];

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command       : SMB_andx_command(header, false, offset+offsetof(andx_command), andx.command);
} &let {
	proc : bool = $context.connection.proc_smb1_tree_connect_andx_response(header, this);
};
