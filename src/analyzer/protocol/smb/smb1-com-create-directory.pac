refine connection SMB_Conn += {

	function proc_smb1_create_directory_request(header: SMB_Header, val: SMB1_create_directory_request): bool
		%{
		if ( smb1_create_directory_request )
			zeek::BifEvent::enqueue_smb1_create_directory_request(zeek_analyzer(), zeek_analyzer()->Conn(),
			                                                SMBHeaderVal(header),
			                                                smb_string2stringval(${val.directory_name}));
		return true;
		%}
	function proc_smb1_create_directory_response(header: SMB_Header, val: SMB1_create_directory_response): bool
		%{
		if ( smb1_create_directory_response )
			zeek::BifEvent::enqueue_smb1_create_directory_response(zeek_analyzer(),
			                                                 zeek_analyzer()->Conn(),
			                                                 SMBHeaderVal(header));
		return true;
		%}

};

type SMB1_create_directory_request(header: SMB_Header) = record {
	word_count      : uint8;
	byte_count      : uint16;
	buffer_format   : uint8;
	directory_name  : SMB_string(header.unicode, offsetof(directory_name));
} &let {
	proc : bool = $context.connection.proc_smb1_create_directory_request(header, this);
};

type SMB1_create_directory_response(header: SMB_Header) = record {
	word_count      : uint8;
	byte_count      : uint16;
} &let {
	proc : bool = $context.connection.proc_smb1_create_directory_response(header, this);
};
