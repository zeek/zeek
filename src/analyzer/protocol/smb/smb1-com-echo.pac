refine connection SMB_Conn += {

	function proc_smb1_echo_request(header: SMB_Header, val: SMB1_echo_request): bool
		%{
		if ( smb1_echo_request )
			zeek::BifEvent::enqueue_smb1_echo_request(zeek_analyzer(), zeek_analyzer()->Conn(),
			                                    ${val.echo_count}, to_stringval(${val.data}));
		return true;
		%}

	function proc_smb1_echo_response(header: SMB_Header, val: SMB1_echo_response): bool
		%{
		if ( smb1_echo_response )
			zeek::BifEvent::enqueue_smb1_echo_response(zeek_analyzer(), zeek_analyzer()->Conn(),
			                                     ${val.seq_num}, to_stringval(${val.data}));
		return true;
		%}

};


# http://msdn.microsoft.com/en-us/library/ee441746.aspx
type SMB1_echo_request(header: SMB_Header) = record {
	word_count : uint8;
	echo_count : uint16;

	byte_count : uint16;
	data       : bytestring &length=byte_count;
} &let {
	proc : bool = $context.connection.proc_smb1_echo_request(header, this);
};

# http://msdn.microsoft.com/en-us/library/ee441626.aspx
type SMB1_echo_response(header: SMB_Header) = record {
	word_count : uint8;
	seq_num    : uint16;

	byte_count : uint16;
	data       : bytestring &length=byte_count;
} &let {
	proc : bool = $context.connection.proc_smb1_echo_response(header, this);
};
