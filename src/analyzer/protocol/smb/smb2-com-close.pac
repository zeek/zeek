refine connection SMB_Conn += {

	function proc_smb2_close_request(h: SMB2_Header, val: SMB2_close_request): bool
		%{
		if ( smb2_close_request )
			{
			zeek::BifEvent::enqueue_smb2_close_request(bro_analyzer(),
			                                     bro_analyzer()->Conn(),
			                                     BuildSMB2HeaderVal(h),
			                                     BuildSMB2GUID(${val.file_id}));
			}

		zeek::file_mgr->EndOfFile(bro_analyzer()->GetAnalyzerTag(),
		                          bro_analyzer()->Conn(), h->is_orig());

		return true;
		%}

	function proc_smb2_close_response(h: SMB2_Header, val: SMB2_close_response): bool
		%{
		if ( smb2_close_response )
			{
			auto resp = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::CloseResponse);

			resp->Assign(0, zeek::val_mgr->Count(${val.alloc_size}));
			resp->Assign(1, zeek::val_mgr->Count(${val.eof}));
			resp->Assign(2, SMB_BuildMACTimes(${val.last_write_time},
			                                  ${val.last_access_time},
			                                  ${val.creation_time},
			                                  ${val.change_time}));
			resp->Assign(3, smb2_file_attrs_to_bro(${val.file_attrs}));

			zeek::BifEvent::enqueue_smb2_close_response(bro_analyzer(),
			                                      bro_analyzer()->Conn(),
			                                      BuildSMB2HeaderVal(h),
			                                      std::move(resp));
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
