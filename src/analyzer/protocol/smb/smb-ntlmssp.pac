refine connection SMB_Conn += {
	function unicode_to_ascii(s: bytestring, length: uint16, is_unicode: bool): bytestring
		%{
		if ( !is_unicode ) return s;

		char* buf;

		buf = new char[(length/2) + 1];
		
		for ( int i = 0; i < length; i += 2 )
			buf[i/2] = s[i];
		buf[length/2] = 0;
		return bytestring((uint8*) buf, (length/2));
		%}

	function build_negotiate_flag_record(val: SMB_NTLM_Negotiate_Flags): BroVal
		%{
		RecordVal* flags = new RecordVal(BifType::Record::SMB::NTLMNegotiateFlags);
		flags->Assign(0, new Val(${val.negotiate_56}, 							TYPE_BOOL));
		flags->Assign(1, new Val(${val.negotiate_key_exch}, 					TYPE_BOOL));
		flags->Assign(2, new Val(${val.negotiate_128}, 							TYPE_BOOL));
		flags->Assign(3, new Val(${val.negotiate_version}, 						TYPE_BOOL));
		flags->Assign(4, new Val(${val.negotiate_target_info}, 					TYPE_BOOL));

		flags->Assign(5, new Val(${val.request_non_nt_session_key}, 			TYPE_BOOL));
		flags->Assign(6, new Val(${val.negotiate_identify}, 					TYPE_BOOL));
		flags->Assign(7, new Val(${val.negotiate_extended_sessionsecurity}, 	TYPE_BOOL));
		flags->Assign(8, new Val(${val.target_type_server}, 					TYPE_BOOL));
		flags->Assign(9, new Val(${val.target_type_domain}, 					TYPE_BOOL));

		flags->Assign(10, new Val(${val.negotiate_always_sign}, 				TYPE_BOOL));
		flags->Assign(11, new Val(${val.negotiate_oem_workstation_supplied}, 	TYPE_BOOL));
		flags->Assign(12, new Val(${val.negotiate_oem_domain_supplied}, 		TYPE_BOOL));
		flags->Assign(13, new Val(${val.negotiate_anonymous_connection}, 		TYPE_BOOL));
		flags->Assign(14, new Val(${val.negotiate_ntlm}, 						TYPE_BOOL));

		flags->Assign(15, new Val(${val.negotiate_lm_key}, 						TYPE_BOOL));
		flags->Assign(16, new Val(${val.negotiate_datagram}, 					TYPE_BOOL));
		flags->Assign(17, new Val(${val.negotiate_seal}, 						TYPE_BOOL));
		flags->Assign(18, new Val(${val.negotiate_sign}, 						TYPE_BOOL));
		flags->Assign(19, new Val(${val.request_target}, 						TYPE_BOOL));

		flags->Assign(20, new Val(${val.negotiate_oem}, 						TYPE_BOOL));
		flags->Assign(21, new Val(${val.negotiate_unicode}, 					TYPE_BOOL));

		return flags;
		%}

	function build_version_record(val: SMB_NTLM_Version): BroVal
		%{
		RecordVal* result = new RecordVal(BifType::Record::SMB::NTLMVersion);
		result->Assign(0, new Val(${val.major_version}, TYPE_COUNT));
		result->Assign(1, new Val(${val.minor_version}, TYPE_COUNT));
		result->Assign(2, new Val(${val.build_number}, 	TYPE_COUNT));
		result->Assign(3, new Val(${val.ntlm_revision}, TYPE_COUNT));

		return result;
		%}

	function build_av_record(val: SMB_NTLM_AV_Pair_Sequence): BroVal
		%{
		RecordVal* result = new RecordVal(BifType::Record::SMB::NTLMAVs);
		for ( uint i = 0; ${val.pairs[i].id} != 0; i++ ) {
			switch ( ${val.pairs[i].id} ) {
				case 1:
					result->Assign(0, bytestring_to_val(${val.pairs[i].nb_computer_name.data}));
					break;
				case 2:
					result->Assign(1, bytestring_to_val(${val.pairs[i].nb_domain_name.data}));
					break;
				case 3:
					result->Assign(2, bytestring_to_val(${val.pairs[i].dns_computer_name.data}));
					break;
				case 4:
					result->Assign(3, bytestring_to_val(${val.pairs[i].dns_domain_name.data}));
					break;
				case 5:
					result->Assign(4, bytestring_to_val(${val.pairs[i].dns_tree_name.data}));
					break;
				case 6:
					result->Assign(5, new Val(${val.pairs[i].constrained_auth}, TYPE_BOOL));
					break;
				case 7:
					result->Assign(6, filetime2brotime(${val.pairs[i].timestamp}));
					break;
				case 8:
					result->Assign(7, new Val(${val.pairs[i].single_host.machine_id}, TYPE_COUNT));
					break;
				case 9:
					result->Assign(8, bytestring_to_val(${val.pairs[i].target_name.data}));
					break;
			}
		}
		return result;
		%}

	function proc_smb_ntlm_ssp(header: SMB_Header, val:SMB_NTLM_SSP): bool
		%{
		if ( ${val.gssapi.is_init} )
			return true;
		for ( uint i = 0; i < ${val.gssapi.resp.args}->size(); ++i )
			{
			switch ( ${val.gssapi.resp.args[i].seq_meta.index} )
				{
				case 0:
					if ( ${val.gssapi.resp.args[i].args.neg_state} == 0 )
					 	BifEvent::generate_smb_ntlm_accepted(bro_analyzer(), bro_analyzer()->Conn(), BuildHeaderVal(header));
					break;
				default:
					break;
				}
			}
		return true;
		%}

	function proc_smb_ntlm_negotiate(header: SMB_Header, val: SMB_NTLM_Negotiate): bool
		%{
		RecordVal* result = new RecordVal(BifType::Record::SMB::NTLMNegotiate);
		result->Assign(0, build_negotiate_flag_record(${val.flags}));

		if ( ${val.flags.negotiate_oem_domain_supplied} )
			result->Assign(1, bytestring_to_val(${val.domain_name.string.data}));

		if ( ${val.flags.negotiate_oem_workstation_supplied} )
			result->Assign(2, bytestring_to_val(${val.workstation.string.data}));

		if ( ${val.flags.negotiate_version} )
			result->Assign(3, build_version_record(${val.version}));

		BifEvent::generate_smb_ntlm_negotiate(bro_analyzer(), bro_analyzer()->Conn(), BuildHeaderVal(header), result);
		
		return true;
		%}
		
	function proc_smb_ntlm_challenge(header: SMB_Header, val: SMB_NTLM_Challenge): bool
		%{
		RecordVal* result = new RecordVal(BifType::Record::SMB::NTLMChallenge);
		result->Assign(0, build_negotiate_flag_record(${val.flags}));

		if ( ${val.flags.request_target} )
			result->Assign(1, bytestring_to_val(${val.target_name.string.data}));

		if ( ${val.flags.negotiate_version} )
			result->Assign(2, build_version_record(${val.version}));

		if ( ${val.flags.negotiate_target_info} )
			result->Assign(3, build_av_record(${val.target_info}));
		
		BifEvent::generate_smb_ntlm_challenge(bro_analyzer(), bro_analyzer()->Conn(), BuildHeaderVal(header), result);
		
		return true;
		%}

	function proc_smb_ntlm_authenticate(header: SMB_Header, val: SMB_NTLM_Authenticate): bool
		%{
		RecordVal* result = new RecordVal(BifType::Record::SMB::NTLMAuthenticate);
		result->Assign(0, build_negotiate_flag_record(${val.flags}));

		if ( ${val.domain_name_fields.length} > 0 )
			result->Assign(1, bytestring_to_val(${val.domain_name.string.data}));

		if ( ${val.user_name_fields.length} > 0 )
			result->Assign(2, bytestring_to_val(${val.user_name.string.data}));

		if ( ${val.workstation_fields.length} > 0 )
			result->Assign(3, bytestring_to_val(${val.workstation.string.data}));

		if ( ${val.flags.negotiate_version} )
			result->Assign(4, build_version_record(${val.version}));

		BifEvent::generate_smb_ntlm_authenticate(bro_analyzer(), bro_analyzer()->Conn(), BuildHeaderVal(header), result);

		return true;
		%}

};

type GSSAPI_NEG_TOKEN(header: SMB_Header) = record {
	wrapper 		 : ASN1EncodingMeta;
	have_oid	     : case is_init of {
		true  -> oid: ASN1Encoding;
		false -> no_oid: empty;
	};
	have_init_wrapper: case is_init of {
		true  -> init_wrapper: ASN1EncodingMeta;
		false -> no_init_wrapper: empty;
	};
	msg_type         : case is_init of {
		true  -> init: GSSAPI_NEG_TOKEN_INIT(header);
		false -> resp: GSSAPI_NEG_TOKEN_RESP(header);
	};
} &let {
	is_init: bool = wrapper.tag == 0x60;
};

type GSSAPI_NEG_TOKEN_INIT(header: SMB_Header) = record {
	seq_meta: ASN1EncodingMeta;
	args	: GSSAPI_NEG_TOKEN_INIT_Arg(header)[];
};

type GSSAPI_NEG_TOKEN_INIT_Arg(header: SMB_Header) = record {
	seq_meta: ASN1EncodingMeta;
	args	: GSSAPI_NEG_TOKEN_INIT_Arg_Data(header, seq_meta.index) &length=seq_meta.length;
};

type GSSAPI_NEG_TOKEN_INIT_Arg_Data(header: SMB_Header, index: uint8) = case index of {
	0 -> mech_type_list : ASN1Encoding;
	1 -> req_flags		: ASN1Encoding;
	2 -> mech_token		: SMB_NTLM_SSP_Token(header);
	3 -> mech_list_mic	: ASN1OctetString;
};

type GSSAPI_NEG_TOKEN_RESP(header: SMB_Header) = record {
	seq_meta: ASN1EncodingMeta;
	args	: GSSAPI_NEG_TOKEN_RESP_Arg(header)[];
};

type GSSAPI_NEG_TOKEN_RESP_Arg(header: SMB_Header) = record {
	seq_meta: ASN1EncodingMeta;
	args	: GSSAPI_NEG_TOKEN_RESP_Arg_Data(header, seq_meta.index) &length=seq_meta.length;
};

type GSSAPI_NEG_TOKEN_RESP_Arg_Data(header: SMB_Header, index: uint8) = case index of {
	0 -> neg_state		: ASN1Integer;
	1 -> supported_mech	: ASN1Encoding;
	2 -> response_token	: SMB_NTLM_SSP_Token(header);
	3 -> mech_list_mic	: ASN1OctetString;
};

type SMB_NTLM_SSP(header: SMB_Header) = record {
	gssapi: GSSAPI_NEG_TOKEN(header);
} &let {
	proc:        bool = $context.connection.proc_smb_ntlm_ssp(header, this);
};

type SMB_NTLM_SSP_Token(header: SMB_Header) = record {
	meta		: ASN1EncodingMeta;
	signature	: bytestring &length=8;
	msg_type 	: uint32;
	msg      	: case msg_type of {
	 	1 -> negotiate   	: SMB_NTLM_Negotiate(header, offsetof(msg) - offsetof(signature));
		2 -> challenge		: SMB_NTLM_Challenge(header, offsetof(msg) - offsetof(signature));
		3 -> authenticate	: SMB_NTLM_Authenticate(header, offsetof(msg) - offsetof(signature));
	};	 
};

type SMB_NTLM_Negotiate(header: SMB_Header, offset: uint16) = record {
	flags		   		: SMB_NTLM_Negotiate_Flags;
	domain_name_fields 	: SMB_NTLM_StringData;
	workstation_fields	: SMB_NTLM_StringData;
	version_present	  	: case flags.negotiate_version of {
		true  -> version	: SMB_NTLM_Version;
		false -> no_version	: empty;
	};
	payload		   		: bytestring &restofdata;
} &let {
	absolute_offset	: uint16 = offsetof(payload) + offset;
	domain_name	   	: SMB_NTLM_String(domain_name_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(flags.negotiate_oem_domain_supplied);
	workstation	   	: SMB_NTLM_String(workstation_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(flags.negotiate_oem_workstation_supplied);
	proc		   	: bool = $context.connection.proc_smb_ntlm_negotiate(header, this);
};

type SMB_NTLM_Challenge(header: SMB_Header, offset: uint16) = record {
	target_name_fields	: SMB_NTLM_StringData;
	flags		   		: SMB_NTLM_Negotiate_Flags;
	challenge	   		: uint64;
	reserved	   		: padding[8];
	target_info_fields 	: SMB_NTLM_StringData;
	version_present	   	: case flags.negotiate_version of {
		true  -> version	: SMB_NTLM_Version;
		false -> no_version	: empty;
	};
	payload            	: bytestring &restofdata;
} &let {
	absolute_offset	: uint16 = offsetof(payload) + offset;
	target_name	   	: SMB_NTLM_String(target_name_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(flags.request_target);
	target_info	   	: SMB_NTLM_AV_Pair_Sequence(target_info_fields.offset - absolute_offset) withinput payload &if(flags.negotiate_target_info);
	proc		   	: bool = $context.connection.proc_smb_ntlm_challenge(header, this);
};

type SMB_NTLM_Authenticate(header: SMB_Header, offset: uint16) = record {
	lm_challenge_response_fields: SMB_NTLM_StringData;
	nt_challenge_response_fields: SMB_NTLM_StringData;
	domain_name_fields	     	: SMB_NTLM_StringData;
	user_name_fields	     	: SMB_NTLM_StringData;
	workstation_fields	     	: SMB_NTLM_StringData;
	encrypted_session_key_fields: SMB_NTLM_StringData;
	flags		             	: SMB_NTLM_Negotiate_Flags;
	version_present	   			: case flags.negotiate_version of {
		true  -> version	: SMB_NTLM_Version;
		false -> no_version	: empty;
	};

#   Windows NT, 2000, XP, and 2003 don't have the MIC field
#	TODO - figure out how to parse this for those that do have it
#	mic		             		: bytestring &length=16;

	payload			     		: bytestring &restofdata;
} &let {
	absolute_offset			: uint16 = offsetof(payload) + offset;
	domain_name				: SMB_NTLM_String(domain_name_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(domain_name_fields.length > 0);
	user_name				: SMB_NTLM_String(user_name_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(user_name_fields.length > 0);
	workstation				: SMB_NTLM_String(workstation_fields, absolute_offset , flags.negotiate_unicode) withinput payload &if(workstation_fields.length > 0);
	encrypted_session_key	: SMB_NTLM_String(encrypted_session_key_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(flags.negotiate_key_exch);
	proc					: bool = $context.connection.proc_smb_ntlm_authenticate(header, this);
};

type SMB_NTLM_Version = record {
	major_version	: uint8;
	minor_version	: uint8;
	build_number	: uint16;
	reserved		: padding[3];
	ntlm_revision	: uint8;
};

type SMB_NTLM_StringData = record {
	length     : uint16;
	max_length : uint16;
	offset	   : uint32;
};

type SMB_Fixed_Length_String(unicode: bool) = record {
	s: bytestring &restofdata;
} &let {
	data: bytestring = $context.connection.unicode_to_ascii(s, sizeof(s), unicode);
};

type SMB_NTLM_String(fields: SMB_NTLM_StringData, offset: uint16, unicode: bool) = record {
	      : padding to fields.offset - offset;
	string: SMB_Fixed_Length_String(unicode) &length=fields.length;
};

type SMB_NTLM_AV_Pair_Sequence(offset: uint16) = record {
	     : padding to offset;
	pairs: SMB_NTLM_AV_Pair[] &until ($element.last);
};

type SMB_NTLM_AV_Pair = record {
	id         : uint16;
	length     : uint16;
	value_case : case id of {
		0x0000 -> av_eol            : empty;
		0x0001 -> nb_computer_name  : SMB_Fixed_Length_String(true) &length=length;
		0x0002 -> nb_domain_name    : SMB_Fixed_Length_String(true) &length=length;
		0x0003 -> dns_computer_name : SMB_Fixed_Length_String(true) &length=length;
		0x0004 -> dns_domain_name   : SMB_Fixed_Length_String(true) &length=length;
		0x0005 -> dns_tree_name     : SMB_Fixed_Length_String(true) &length=length;
		0x0006 -> av_flags          : uint32;
		0x0007 -> timestamp         : uint64;
		0x0008 -> single_host       : SMB_NTLM_Single_Host;
		0x0009 -> target_name       : SMB_Fixed_Length_String(true) &length=length;
		0x000a -> channel_bindings  : uint16;
	};
} &let {
	last		 	: bool = ( id == 0x0000);
	# av_flags refinement
	constrained_auth: bool = (av_flags & 0x00000001) > 0 &if ( id == 0x0006);
	mic_present     : bool = (av_flags & 0x00000002) > 0 &if ( id == 0x0006);
	untrusted_source: bool = (av_flags & 0x00000004) > 0 &if ( id == 0x0006);	
};

type SMB_NTLM_Single_Host = record {
	size	    : uint32;
	padpad	    : padding[4];
	data_present: uint32;
	optional    : case custom_data_present of {
		true  -> custom_data : bytestring &length=4;
		false -> nothing     : empty;
	};
	machine_id	: uint32;
} &let {
	custom_data_present: bool = (data_present & 0x00000001) > 0;
};

type SMB_LM_Response(offset: uint16) = record {
	# This can be either LM (24 byte response) or
	# LMv2 (16 byte response + 8 byte client challenge. No way to
	# know for sure.
	padpad  : padding to offset;
	response: bytestring &length=24;
};

type SMB_NTLM_Response(offset: uint16) = record {
	padpad  : padding to offset;
	response: bytestring &length=24;
};

type SMB_NTLMv2_Response(flags: SMB_NTLM_Negotiate_Flags, offset: uint16) = record {
	padpad          : padding to offset;
	response        : bytestring &length=16;
	client_challenge: SMB_NTLMv2_Client_Challenge(flags);
};

type SMB_NTLMv2_Client_Challenge(flags: SMB_NTLM_Negotiate_Flags) = record {
	resp_type	 	: uint8;
	max_resp_type	: uint8;
	reserved	 	: padding[6];
	timestamp	 	: uint64;
	client_challenge: bytestring &length=8;
	reserved2	 	: padding[4];
	av_pairs	 	: SMB_NTLM_AV_Pair_Sequence(0);
};

type SMB_NTLM_Negotiate_Flags = record {
	flags: uint32;
} &let {
	negotiate_56						: bool = (flags & 0x80000000) > 0;
	negotiate_key_exch					: bool = (flags & 0x40000000) > 0;
	negotiate_128						: bool = (flags & 0x20000000) > 0;
	
	negotiate_version					: bool = (flags & 0x02000000) > 0;
	
	negotiate_target_info				: bool = (flags & 0x00800000) > 0;
	request_non_nt_session_key			: bool = (flags & 0x00400000) > 0;
	negotiate_identify					: bool = (flags & 0x00100000) > 0;
	
	negotiate_extended_sessionsecurity	: bool = (flags & 0x00040000) > 0;
	target_type_server					: bool = (flags & 0x00020000) > 0;
	target_type_domain					: bool = (flags & 0x00010000) > 0;

	negotiate_always_sign				: bool = (flags & 0x00008000) > 0;
	negotiate_oem_workstation_supplied	: bool = (flags & 0x00002000) > 0;
	negotiate_oem_domain_supplied		: bool = (flags & 0x00001000) > 0;

	negotiate_anonymous_connection		: bool = (flags & 0x00000400) > 0;
	negotiate_ntlm						: bool = (flags & 0x00000100) > 0;

	negotiate_lm_key					: bool = (flags & 0x00000080) > 0;
	negotiate_datagram					: bool = (flags & 0x00000040) > 0;
	negotiate_seal						: bool = (flags & 0x00000020) > 0;

	negotiate_sign						: bool = (flags & 0x00000008) > 0;
	request_target						: bool = (flags & 0x00000004) > 0;
	negotiate_oem						: bool = (flags & 0x00000002) > 0;
	negotiate_unicode					: bool = (flags & 0x00000001) > 0;

	is_oem								: bool = !negotiate_unicode && negotiate_oem;
	is_invalid							: bool = !negotiate_unicode && !negotiate_oem;
};
