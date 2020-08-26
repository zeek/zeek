refine connection SMB_Conn += {

	function proc_smb1_nt_cancel_request(header: SMB_Header, val: SMB1_nt_cancel_request): bool
		%{
		if ( smb1_nt_cancel_request )
			zeek::BifEvent::enqueue_smb1_nt_cancel_request(zeek_analyzer(),
			                                         zeek_analyzer()->Conn(),
			                                         SMBHeaderVal(header));
		return true;
		%}

};

type SMB1_nt_cancel_request(header: SMB_Header) = record {
	word_count : uint8;

	byte_count : uint16;
} &let {
	proc : bool = $context.connection.proc_smb1_nt_cancel_request(header, this);
};
