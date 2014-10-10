refine connection SMB_Conn += {

	function proc_smb1_close_request(h: SMB_Header, val: SMB1_close_request): bool
		%{
		if ( smb1_close_request )
			BifEvent::generate_smb1_close_request(bro_analyzer(),
			                                     bro_analyzer()->Conn(),
			                                     BuildHeaderVal(h),
			                                     ${val.file_id});

		// This is commented out for the moment because it caused problems
		// with extraction because the file kept having the same name due
		// to repeatedly having the same file uid.  This results in files
		// effectively falling of SMB solely by expiration instead of 
		// manually being closed.

		//file_mgr->EndOfFile(bro_analyzer()->GetAnalyzerTag(),
		//		    bro_analyzer()->Conn(), h->is_orig());

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
