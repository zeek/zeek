refine connection SMB_Conn += {

	function proc_smb1_tree_connect_andx_request(header: SMB_Header, val: SMB1_tree_connect_andx_request): bool
		%{
		if ( smb1_tree_connect_andx_request )
			BifEvent::generate_smb1_tree_connect_andx_request(bro_analyzer(),
			                                                  bro_analyzer()->Conn(),
			                                                  BuildHeaderVal(header),
			                                                  smb_string2stringval(${val.path}),
			                                                  smb_string2stringval(${val.service}));
		return true;
		%}

	function proc_smb1_tree_connect_andx_response(header: SMB_Header, val: SMB1_tree_connect_andx_response): bool
		%{
		set_tree_is_pipe(${header.tid}, strcmp((const char*) smb_string2stringval(${val.service})->Bytes(), "IPC") == 0);
		if ( smb1_tree_connect_andx_response )
			BifEvent::generate_smb1_tree_connect_andx_response(bro_analyzer(),
			                                                   bro_analyzer()->Conn(),
			                                                   BuildHeaderVal(header),
			                                                   smb_string2stringval(${val.service}),
			                                                   smb_string2stringval(${val.native_file_system}));

		return true;
		%}

};

type SMB1_tree_connect_andx_request(header: SMB_Header) = record {
	word_count      : uint8;
	andx	        : SMB_andx;
	flags	        : uint16;
	password_length : uint16;
	
	byte_count      : uint16;
	password        : uint8[password_length];
	path            : SMB_string(header.unicode, offsetof(path));
	service         : SMB_string(0, offsetof(service));
} &let {
	proc : bool = $context.connection.proc_smb1_tree_connect_andx_request(header, this);
};

type SMB1_tree_connect_andx_response(header: SMB_Header) = record {
	word_count         : uint8;
	andx		   : SMB_andx;
	optional_support   : uint16;
	pad                : padding[(word_count-3)*2];
	
	byte_count         : uint16;
	service            : SMB_string(0, offsetof(service));
	native_file_system : SMB_string(header.unicode, offsetof(native_file_system));
} &let {
	proc : bool = $context.connection.proc_smb1_tree_connect_andx_response(header, this);
};

