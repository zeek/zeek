refine connection SMB_Conn += {

	function proc_smb1_query_information_request(header: SMB_Header, val: SMB1_query_information_request): bool
		%{
		if ( smb1_query_information_request )
			zeek::BifEvent::enqueue_smb1_query_information_request(zeek_analyzer(),
			                                                 zeek_analyzer()->Conn(),
			                                                 SMBHeaderVal(header),
			                                                 smb_string2stringval(${val.filename}));
		return true;
		%}

	function proc_smb1_query_information_response(header: SMB_Header, val: SMB1_query_information_response): bool
		%{
		//printf("query_information_response\n");
		return true;
		%}

};

type SMB1_query_information_request(header: SMB_Header) = record {
	word_count    : uint8;

	byte_count    : uint16;
	buffer_format : uint8;
	filename      : SMB_string(header.unicode, offsetof(filename));
} &let {
	proc : bool = $context.connection.proc_smb1_query_information_request(header, this);
};

type SMB1_query_information_response(header: SMB_Header) = record {
	word_count      : uint8;
	file_attribs    : uint16;
	last_write_time : SMB_time;
	file_size       : uint32;
	reserved        : uint16[5];
	byte_count      : uint16;
} &let {
	proc : bool = $context.connection.proc_smb1_query_information_response(header, this);
};
