refine connection SMB_Conn += {

	function proc_smb2_negotiate_request(h: SMB2_Header, val: SMB2_negotiate_request) : bool
		%{
		if ( smb2_negotiate_request )
			{
			VectorVal* dialects = new VectorVal(index_vec);
			for ( unsigned int i = 0; i < ${val.dialects}->size(); ++i )
				{
				dialects->Assign(i, new Val((*${val.dialects})[i], TYPE_COUNT));
				}
			BifEvent::generate_smb2_negotiate_request(bro_analyzer(), bro_analyzer()->Conn(),
			                                          BuildSMB2HeaderVal(h),
			                                          dialects);
			}

		return true;
		%}

	function proc_smb2_negotiate_response(h: SMB2_Header, val: SMB2_negotiate_response) : bool
		%{
		if ( smb2_negotiate_response )
			{
			RecordVal* nr = new RecordVal(BifType::Record::SMB2::NegotiateResponse);

			nr->Assign(0, new Val(${val.dialect_revision}, TYPE_COUNT));
			nr->Assign(1, new Val(${val.security_mode}, TYPE_COUNT));
			nr->Assign(2, BuildSMB2GUID(${val.server_guid})),
			nr->Assign(3, filetime2brotime(${val.system_time}));
			nr->Assign(4, filetime2brotime(${val.server_start_time}));
			BifEvent::generate_smb2_negotiate_response(bro_analyzer(), bro_analyzer()->Conn(),
			                                           BuildSMB2HeaderVal(h),
			                                           nr);
			}

		return true;
		%}
};

type SMB2_negotiate_request(header: SMB2_Header) = record {
	structure_size    : uint16;          # client MUST set this to 36
	dialect_count     : uint16;          # must be > 0
	security_mode     : uint16;          # there is a list of required modes
	reserved          : padding[2];      # must be set to 0
	capabilities      : uint32;          # must be set to 0
	client_guid       : SMB2_guid;       # guid if client implements SMB 2.1 dialect, otherwise set to 0
	client_start_time : SMB_timestamp;   # must be set to 0
	dialects          : uint16[dialect_count];
} &byteorder=littleendian, &let {
	proc : bool = $context.connection.proc_smb2_negotiate_request(header, this);
};

type SMB2_negotiate_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	security_mode     : uint16;
	dialect_revision  : uint16;
	reserved          : padding[2];
	server_guid       : SMB2_guid;
	capabilities      : uint32;
	max_transact_size : uint32;
	max_read_size     : uint32;
	max_write_size    : uint32;
	system_time       : SMB_timestamp;
	server_start_time : SMB_timestamp;
	security_offset   : uint16;
	security_length   : uint16;
	pad1              : padding to security_offset - header.head_length;
	security_blob     : bytestring &length=security_length;
} &byteorder=littleendian, &let {
	proc : bool = $context.connection.proc_smb2_negotiate_response(header, this);
	gssapi_proc : bool = $context.connection.forward_gssapi(security_blob, false);

};
