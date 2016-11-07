refine connection SMB_Conn += {

	function proc_smb2_close_request(h: SMB2_Header, val: SMB2_close_request): bool
		%{
		if ( smb2_close_request )
			{
			BifEvent::generate_smb2_close_request(bro_analyzer(),
			                                      bro_analyzer()->Conn(),
			                                      BuildSMB2HeaderVal(h),
			                                      BuildSMB2GUID(${val.file_id}));
			}

		file_mgr->EndOfFile(bro_analyzer()->GetAnalyzerTag(),
		                    bro_analyzer()->Conn(), h->is_orig());

		return true;
		%}

	function proc_smb2_close_response(h: SMB2_Header, val: SMB2_close_response): bool
		%{
		if ( smb2_close_response )
			{
			RecordVal* resp = new RecordVal(BifType::Record::SMB2::CloseResponse);

			resp->Assign(0, new Val(${val.alloc_size}, TYPE_COUNT));
			resp->Assign(1, new Val(${val.eof}, TYPE_COUNT));
			resp->Assign(2, SMB_BuildMACTimes(${val.last_write_time},
			                                  ${val.last_access_time},
			                                  ${val.creation_time},
			                                  ${val.change_time}));
			resp->Assign(3, smb2_file_attrs_to_bro(${val.file_attrs}));

			BifEvent::generate_smb2_close_response(bro_analyzer(),
			                                       bro_analyzer()->Conn(),
			                                       BuildSMB2HeaderVal(h),
			                                       resp);
			}

		return true;
		%}
};

type SMB2_close_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	flags               : uint16;
	reserved            : uint32;
	file_id             : SMB2_guid;
} &let {
	proc: bool = $context.connection.proc_smb2_close_request(header, this);
};

type SMB2_close_response(header: SMB2_Header) = record {
	structure_size      : uint16;
	flags               : uint16;
	reserved            : uint32;

	creation_time       : SMB_timestamp;
	last_access_time    : SMB_timestamp;
	last_write_time     : SMB_timestamp;
	change_time         : SMB_timestamp;
	alloc_size          : uint64;
	eof                 : uint64;
	file_attrs          : SMB2_file_attributes;
} &let {
	proc: bool = $context.connection.proc_smb2_close_response(header, this);
};
