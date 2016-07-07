refine connection SMB_Conn += {

	function proc_smb2_session_setup_request(h: SMB2_Header, val: SMB2_session_setup_request): bool
		%{
		if ( smb2_session_setup_request )
			{
			RecordVal* req = new RecordVal(BifType::Record::SMB2::SessionSetupRequest);
			req->Assign(0, new Val(${val.security_mode}, TYPE_COUNT));

			BifEvent::generate_smb2_session_setup_request(bro_analyzer(),
			                                              bro_analyzer()->Conn(),
			                                              BuildSMB2HeaderVal(h),
			                                              req);
			}

		return true;
		%}

	function proc_smb2_session_setup_response(h: SMB2_Header, val: SMB2_session_setup_response): bool
		%{
		if ( smb2_session_setup_response )
			{
			RecordVal* flags = new RecordVal(BifType::Record::SMB2::SessionSetupFlags);
			flags->Assign(0, new Val(${val.flag_guest}, TYPE_BOOL));
			flags->Assign(1, new Val(${val.flag_anonymous}, TYPE_BOOL));
			flags->Assign(2, new Val(${val.flag_encrypt}, TYPE_BOOL));

			RecordVal* resp = new RecordVal(BifType::Record::SMB2::SessionSetupResponse);
			resp->Assign(0, flags);

			BifEvent::generate_smb2_session_setup_response(bro_analyzer(),
			                                               bro_analyzer()->Conn(),
			                                               BuildSMB2HeaderVal(h),
			                                               resp);
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
