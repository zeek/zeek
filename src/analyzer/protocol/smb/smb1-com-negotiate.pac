# This is an original Core Protocol command.
#
# This command is used to initiate an SMB connection between the
# client and the server. An SMB_COM_NEGOTIATE exchange MUST be
# completed before any other SMB messages are sent to the server.
#
# There MUST be only one SMB_COM_NEGOTIATE exchange per SMB
# connection. Subsequent SMB_COM_NEGOTIATE requests received by the
# server MUST be rejected with error responses. The server MUST NOT
# take any other action.

refine connection SMB_Conn += {

	function proc_smb1_negotiate_request(header: SMB_Header, val: SMB1_negotiate_request): bool
		%{
		if ( smb1_negotiate_request )
			{
			auto dialects = make_intrusive<VectorVal>(zeek::id::string_vec);

			for ( unsigned int i = 0; i < ${val.dialects}->size(); ++i )
				{
				auto dia = smb_string2stringval((*${val.dialects})[i]->name());
				dialects->Assign(i, std::move(dia));
				}

			BifEvent::enqueue_smb1_negotiate_request(bro_analyzer(), bro_analyzer()->Conn(),
			                                         SMBHeaderVal(header),
			                                         std::move(dialects));
			}

		return true;
		%}

	function proc_smb1_negotiate_response(header: SMB_Header, val: SMB1_negotiate_response): bool
		%{
		if ( smb1_negotiate_response )
			{
			auto response = make_intrusive<RecordVal>(BifType::Record::SMB1::NegotiateResponse);

			switch ( ${val.word_count} )
				{
				case 0x01:
					{
					auto core = make_intrusive<RecordVal>(BifType::Record::SMB1::NegotiateResponseCore);
					core->Assign(0, val_mgr->Count(${val.dialect_index}));

					response->Assign(0, std::move(core));
					}
					break;

				case 0x0d:
					{
					auto security = make_intrusive<RecordVal>(BifType::Record::SMB1::NegotiateResponseSecurity);
					security->Assign(0, val_mgr->Bool(${val.lanman.security_user_level}));
					security->Assign(1, val_mgr->Bool(${val.lanman.security_challenge_response}));

					auto raw = make_intrusive<RecordVal>(BifType::Record::SMB1::NegotiateRawMode);
					raw->Assign(0, val_mgr->Bool(${val.lanman.raw_read_supported}));
					raw->Assign(1, val_mgr->Bool(${val.lanman.raw_write_supported}));

					auto lanman = make_intrusive<RecordVal>(BifType::Record::SMB1::NegotiateResponseLANMAN);
					lanman->Assign(0, val_mgr->Count(${val.word_count}));
					lanman->Assign(1, val_mgr->Count(${val.dialect_index}));
					lanman->Assign(2, std::move(security));
					lanman->Assign(3, val_mgr->Count(${val.lanman.max_buffer_size}));
					lanman->Assign(4, val_mgr->Count(${val.lanman.max_mpx_count}));

					lanman->Assign(5, val_mgr->Count(${val.lanman.max_number_vcs}));
					lanman->Assign(6, std::move(raw));
					lanman->Assign(7, val_mgr->Count(${val.lanman.session_key}));
					lanman->Assign(8, time_from_lanman(${val.lanman.server_time}, ${val.lanman.server_date}, ${val.lanman.server_tz}));
					lanman->Assign(9, to_stringval(${val.lanman.encryption_key}));

					lanman->Assign(10, smb_string2stringval(${val.lanman.primary_domain}));

					response->Assign(1, std::move(lanman));
					}
					break;

				case 0x11:
					{
					auto security = make_intrusive<RecordVal>(BifType::Record::SMB1::NegotiateResponseSecurity);
					security->Assign(0, val_mgr->Bool(${val.ntlm.security_user_level}));
					security->Assign(1, val_mgr->Bool(${val.ntlm.security_challenge_response}));
					security->Assign(2, val_mgr->Bool(${val.ntlm.security_signatures_enabled}));
					security->Assign(3, val_mgr->Bool(${val.ntlm.security_signatures_required}));

					auto capabilities = make_intrusive<RecordVal>(BifType::Record::SMB1::NegotiateCapabilities);
					capabilities->Assign(0, val_mgr->Bool(${val.ntlm.capabilities_raw_mode}));
					capabilities->Assign(1, val_mgr->Bool(${val.ntlm.capabilities_mpx_mode}));
					capabilities->Assign(2, val_mgr->Bool(${val.ntlm.capabilities_unicode}));
					capabilities->Assign(3, val_mgr->Bool(${val.ntlm.capabilities_large_files}));
					capabilities->Assign(4, val_mgr->Bool(${val.ntlm.capabilities_nt_smbs}));

					capabilities->Assign(5, val_mgr->Bool(${val.ntlm.capabilities_rpc_remote_apis}));
					capabilities->Assign(6, val_mgr->Bool(${val.ntlm.capabilities_status32}));
					capabilities->Assign(7, val_mgr->Bool(${val.ntlm.capabilities_level_2_oplocks}));
					capabilities->Assign(8, val_mgr->Bool(${val.ntlm.capabilities_lock_and_read}));
					capabilities->Assign(9, val_mgr->Bool(${val.ntlm.capabilities_nt_find}));

					capabilities->Assign(10, val_mgr->Bool(${val.ntlm.capabilities_dfs}));
					capabilities->Assign(11, val_mgr->Bool(${val.ntlm.capabilities_infolevel_passthru}));
					capabilities->Assign(12, val_mgr->Bool(${val.ntlm.capabilities_large_readx}));
					capabilities->Assign(13, val_mgr->Bool(${val.ntlm.capabilities_large_writex}));
					capabilities->Assign(14, val_mgr->Bool(${val.ntlm.capabilities_unix}));

					capabilities->Assign(15, val_mgr->Bool(${val.ntlm.capabilities_bulk_transfer}));
					capabilities->Assign(16, val_mgr->Bool(${val.ntlm.capabilities_compressed_data}));
					capabilities->Assign(17, val_mgr->Bool(${val.ntlm.capabilities_extended_security}));

					auto ntlm = make_intrusive<RecordVal>(BifType::Record::SMB1::NegotiateResponseNTLM);
					ntlm->Assign(0, val_mgr->Count(${val.word_count}));
					ntlm->Assign(1, val_mgr->Count(${val.dialect_index}));
					ntlm->Assign(2, std::move(security));
					ntlm->Assign(3, val_mgr->Count(${val.ntlm.max_buffer_size}));
					ntlm->Assign(4, val_mgr->Count(${val.ntlm.max_mpx_count}));

					ntlm->Assign(5, val_mgr->Count(${val.ntlm.max_number_vcs}));
					ntlm->Assign(6, val_mgr->Count(${val.ntlm.max_raw_size}));
					ntlm->Assign(7, val_mgr->Count(${val.ntlm.session_key}));
					ntlm->Assign(8, std::move(capabilities));
					ntlm->Assign(9, filetime2brotime(${val.ntlm.server_time}));

					if ( ${val.ntlm.capabilities_extended_security} == false )
						{
						ntlm->Assign(10, to_stringval(${val.ntlm.encryption_key}));
						ntlm->Assign(11, smb_string2stringval(${val.ntlm.domain_name}));
						}
					else
						{
						ntlm->Assign(12, to_stringval(${val.ntlm.server_guid}));
						}

					response->Assign(2, std::move(ntlm));
					}
					break;
				}
			BifEvent::enqueue_smb1_negotiate_response(bro_analyzer(),
			                                          bro_analyzer()->Conn(),
			                                          SMBHeaderVal(header),
			                                          std::move(response));
			}

		return true;
		%}
};

type SMB_dialect = record {
	buffer_format  : uint8; # must be 0x2 for dialect
	name           : SMB_string(0,0);
};

type SMB1_negotiate_request(header: SMB_Header) = record {
	word_count: uint8;	# must be 0
	byte_count: uint16;
	dialects:   SMB_dialect[] &length=byte_count;
} &let {
	proc : bool = $context.connection.proc_smb1_negotiate_request(header, this);
};

type SMB1_negotiate_response(header: SMB_Header) = record {
	word_count:    uint8;
	dialect_index: uint16;
	response:      case word_count of {
		0x01	-> core   : SMB1_negotiate_core_response;
		0x0d	-> lanman : SMB1_negotiate_lanman_response(header);
		0x11	-> ntlm   : SMB1_negotiate_ntlm_response(header);
	};
} &let {
	proc: bool = $context.connection.proc_smb1_negotiate_response(header, this);
};

type SMB1_negotiate_core_response = record {
	byte_count: uint16;
};

type SMB1_negotiate_lanman_response(header: SMB_Header) = record {
	security_flags        : uint16; # expanded in &let
	max_buffer_size       : uint16;
	max_mpx_count         : uint16;
	max_number_vcs        : uint16;
	raw_mode              : uint16; # expanded in &let
	session_key           : uint32;
	server_time           : SMB_time;
	server_date           : SMB_date;
	server_tz             : uint16;
	encryption_key_length : uint16;
	reserved              : uint16; # must be zero
	byte_count            : uint16; # count of data bytes
	encryption_key        : bytestring &length=encryption_key_length;
	primary_domain        : SMB_string(header.unicode, offsetof(primary_domain));
} &let {
	security_user_level         : bool = ( security_flags & 0x1 ) > 0;
	security_challenge_response : bool = ( security_flags & 0x2 ) > 0;
	raw_read_supported          : bool = ( raw_mode & 0x1 ) > 0;
	raw_write_supported         : bool = ( raw_mode & 0x2 ) > 0;
};

type SMB1_negotiate_ntlm_response(header: SMB_Header) = record {
	security_flags        : uint8;  # Expanded in &let
	max_mpx_count         : uint16;
	max_number_vcs        : uint16;
	max_buffer_size       : uint32;
	max_raw_size          : uint32;
	session_key           : uint32;
	capabilities          : uint32; # Expanded in &let
	server_time           : uint64;
	server_tz             : uint16;
	encryption_key_length : uint8;
	byte_count            : uint16;
	encryption_key_present: case capabilities_extended_security of {
		false	-> encryption_key : bytestring &length=encryption_key_length;
		true	-> no_key         : empty;
	} &requires(capabilities_extended_security);
	domain_name_present: case capabilities_extended_security of {
		false	-> domain_name : SMB_string(header.unicode, offsetof(domain_name_present));
		true	-> no_name     : empty;
	} &requires(capabilities_extended_security);
	server_guid_present: case capabilities_extended_security of {
		true	-> server_guid : bytestring &length=16;
		false	-> no_guid     : empty;
	} &requires(capabilities_extended_security);
	security_blob_present: case capabilities_extended_security of {
		true	-> security_blob : bytestring &length=(byte_count-16);
		false	-> no_blob       : empty;
	} &requires(capabilities_extended_security);
} &let {
	security_user_level             : bool = (security_flags & 0x1) > 0;
	security_challenge_response     : bool = (security_flags & 0x2) > 0;
	security_signatures_enabled     : bool = (security_flags & 0x4) > 0;
	security_signatures_required    : bool = (security_flags & 0x8) > 0;
	capabilities_raw_mode           : bool = (capabilities & 0x1) > 0;
	capabilities_mpx_mode           : bool = (capabilities & 0x2) > 0;
	capabilities_unicode            : bool = (capabilities & 0x4) > 0;
	capabilities_large_files        : bool = (capabilities & 0x8) > 0;
	capabilities_nt_smbs            : bool = (capabilities & 0x10) > 0;
	capabilities_rpc_remote_apis    : bool = (capabilities & 0x20) > 0;
	capabilities_status32           : bool = (capabilities & 0x40) > 0;
	capabilities_level_2_oplocks    : bool = (capabilities & 0x80) > 0;
	capabilities_lock_and_read      : bool = (capabilities & 0x100) > 0;
	capabilities_nt_find            : bool = (capabilities & 0x200) > 0;
	capabilities_dfs                : bool = (capabilities & 0x1000) > 0;
	capabilities_infolevel_passthru : bool = (capabilities & 0x2000) > 0;
	capabilities_large_readx        : bool = (capabilities & 0x4000) > 0;
	capabilities_large_writex       : bool = (capabilities & 0x8000) > 0;
	capabilities_unix               : bool = (capabilities & 0x00800000) > 0;
	capabilities_reserved           : bool = (capabilities & 0x02000000) > 0;
	capabilities_bulk_transfer      : bool = (capabilities & 0x20000000) > 0;
	capabilities_compressed_data    : bool = (capabilities & 0x40000000) > 0;
	capabilities_extended_security  : bool = (capabilities & 0x80000000) > 0;

	gssapi_proc : bool = $context.connection.forward_gssapi(security_blob, false) &if(capabilities_extended_security);
};

