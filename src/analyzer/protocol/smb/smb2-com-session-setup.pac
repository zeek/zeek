refine connection SMB_Conn += {

	function proc_smb2_session_setup_request(h: SMB2_Header, val: SMB2_session_setup_request): bool
		%{
		if ( smb2_session_setup_request )
			{
			auto req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::SessionSetupRequest);
			req->Assign(0, ${val.security_mode});

			zeek::BifEvent::enqueue_smb2_session_setup_request(zeek_analyzer(),
			                                             zeek_analyzer()->Conn(),
			                                             BuildSMB2HeaderVal(h),
			                                             std::move(req));
			}

		return true;
		%}

	function proc_smb2_session_setup_response(h: SMB2_Header, val: SMB2_session_setup_response): bool
		%{
		if ( smb2_session_setup_response )
			{
			auto flags = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::SessionSetupFlags);
			flags->Assign(0, ${val.flag_guest});
			flags->Assign(1, ${val.flag_anonymous});
			flags->Assign(2, ${val.flag_encrypt});

			auto resp = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::SessionSetupResponse);
			resp->Assign(0, std::move(flags));

			zeek::BifEvent::enqueue_smb2_session_setup_response(zeek_analyzer(),
			                                              zeek_analyzer()->Conn(),
			                                              BuildSMB2HeaderVal(h),
			                                              std::move(resp));
			}

		return true;
		%}
};


type SMB2_session_setup_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	vc_number         : uint8;
	security_mode     : uint8;
	capabilities      : uint32;
	channel           : uint32;
	security_offset   : uint16;
	security_length   : uint16;
	pad1              : padding to security_offset - header.head_length;
	security_blob     : bytestring &length=security_length;
} &let {
	proc: bool = $context.connection.proc_smb2_session_setup_request(header, this);
	gssapi_proc : bool = $context.connection.forward_gssapi(security_blob, true);
};

type SMB2_session_setup_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	session_flags     : uint16;
	security_offset   : uint16;
	security_length   : uint16;
	pad1              : padding to security_offset - header.head_length;
	security_blob     : bytestring &length=security_length;
} &let {
	flag_guest     = (session_flags & 0x1) > 0;
	flag_anonymous = (session_flags & 0x2) > 0;
	flag_encrypt   = (session_flags & 0x4) > 0;

	proc: bool = $context.connection.proc_smb2_session_setup_response(header, this);
	gssapi_proc : bool = $context.connection.forward_gssapi(security_blob, false);
};
