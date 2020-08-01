refine connection SMB_Conn += {

	function proc_smb1_close_request(h: SMB_Header, val: SMB1_close_request): bool
		%{
		if ( smb1_close_request )
			zeek::BifEvent::enqueue_smb1_close_request(bro_analyzer(),
			                                     bro_analyzer()->Conn(),
			                                     SMBHeaderVal(h),
			                                     ${val.file_id});

		zeek::file_mgr->EndOfFile(bro_analyzer()->GetAnalyzerTag(),
		                          bro_analyzer()->Conn(), h->is_orig());

		return true;
		%}

};


type SMB1_close_request(header: SMB_Header) = record {
	word_count           : uint8;
	file_id              : uint16;
	last_modified_time   : SMB_timestamp32;

	byte_count           : uint16;
} &let {
	proc : bool = $context.connection.proc_smb1_close_request(header, this);
};
