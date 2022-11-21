
function min(v1: uint32, v2: uint32): uint32
	%{
	return v1 < v2 ? v1 : v2;
	%}

type NTLM_SSP_Token(is_orig: bool) = record {
	signature   : bytestring &length=8;
	msg_type    : uint32;
	msg         : case msg_type of {
		1       -> negotiate    : NTLM_Negotiate(offsetof(msg) - offsetof(signature));
		2       -> challenge    : NTLM_Challenge(offsetof(msg) - offsetof(signature));
		3       -> authenticate : NTLM_Authenticate(offsetof(msg) - offsetof(signature));
		default -> def          : bytestring &restofdata &transient;
	};
} &byteorder=littleendian;

type NTLM_Negotiate(offset: uint16) = record {
	flags               : NTLM_Negotiate_Flags;
	domain_name_fields  : NTLM_StringData;
	workstation_fields  : NTLM_StringData;
	payload             : bytestring &restofdata;
} &let {
	absolute_offset : uint16 = offsetof(payload) + offset;
	version         : NTLM_Version withinput payload &if(flags.negotiate_version && (absolute_offset < min(domain_name_fields.offset, workstation_fields.offset)));
	domain_name     : NTLM_String(domain_name_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(flags.negotiate_oem_domain_supplied);
	workstation     : NTLM_String(workstation_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(flags.negotiate_oem_workstation_supplied);
};

type NTLM_Challenge(offset: uint16) = record {
	target_name_fields  : NTLM_StringData;
	flags               : NTLM_Negotiate_Flags;
	challenge           : uint64;
	reserved            : padding[8];
	target_info_fields  : NTLM_StringData;
	payload             : bytestring &restofdata;
} &let {
	absolute_offset : uint16 = offsetof(payload) + offset;
	version         : NTLM_Version withinput payload &if(flags.negotiate_version && (absolute_offset < min(target_name_fields.offset, target_info_fields.offset)));
	target_name     : NTLM_String(target_name_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(flags.request_target);
	target_info     : NTLM_AV_Pair_Sequence(target_info_fields.offset - absolute_offset) withinput payload &if(flags.negotiate_target_info);
};

type NTLM_Authenticate(offset: uint16) = record {
	lm_challenge_response_fields : NTLM_StringData;
	nt_challenge_response_fields : NTLM_StringData;
	domain_name_fields           : NTLM_StringData;
	user_name_fields             : NTLM_StringData;
	workstation_fields           : NTLM_StringData;
	encrypted_session_key_fields : NTLM_StringData;
	flags                        : NTLM_Negotiate_Flags;

#   Windows NT, 2000, XP, and 2003 don't have the MIC field
#	TODO - figure out how to parse this for those that do have it
#	mic                         : bytestring &length=16;

	payload                     : bytestring &restofdata;
} &let {
	absolute_offset       : uint16 = offsetof(payload) + offset;
	version               : NTLM_Version withinput payload &if(flags.negotiate_version && (absolute_offset < min(min(min(domain_name_fields.offset, user_name_fields.offset), workstation_fields.offset), encrypted_session_key_fields.offset)));
	response              : NTLM_String(nt_challenge_response_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(nt_challenge_response_fields.length > 0);
	domain_name           : NTLM_String(domain_name_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(domain_name_fields.length > 0);
	user_name             : NTLM_String(user_name_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(user_name_fields.length > 0);
	workstation           : NTLM_String(workstation_fields, absolute_offset , flags.negotiate_unicode) withinput payload &if(workstation_fields.length > 0);
	encrypted_session_key : NTLM_String(encrypted_session_key_fields, absolute_offset, flags.negotiate_unicode) withinput payload &if(encrypted_session_key_fields.length > 0);
};

type NTLM_Version = record {
	major_version	: uint8;
	minor_version	: uint8;
	build_number	: uint16;
	reserved		: padding[3];
	ntlm_revision	: uint8;
};

type NTLM_StringData = record {
	length     : uint16;
	max_length : uint16;
	offset     : uint32;
};

type Fixed_Length_String(unicode: bool) = record {
	data: bytestring &restofdata;
};

type NTLM_String(fields: NTLM_StringData, offset: uint16, unicode: bool) = record {
	pad1   : padding to fields.offset - offset;
	string : Fixed_Length_String(unicode) &length=fields.length;
};

type NTLM_AV_Pair_Sequence(offset: uint16) = record {
	pad1  : padding to offset;
	pairs : NTLM_AV_Pair[] &until($element.last);
};

type NTLM_AV_Pair = record {
	id         : uint16;
	length     : uint16;
	value_case : case id of {
		0x0000 -> av_eol            : empty;
		0x0001 -> nb_computer_name  : Fixed_Length_String(true) &length=length;
		0x0002 -> nb_domain_name    : Fixed_Length_String(true) &length=length;
		0x0003 -> dns_computer_name : Fixed_Length_String(true) &length=length;
		0x0004 -> dns_domain_name   : Fixed_Length_String(true) &length=length;
		0x0005 -> dns_tree_name     : Fixed_Length_String(true) &length=length;
		0x0006 -> av_flags          : uint32;
		0x0007 -> timestamp         : uint64;
		0x0008 -> single_host       : NTLM_Single_Host;
		0x0009 -> target_name       : Fixed_Length_String(true) &length=length;
		0x000a -> channel_bindings  : uint16;
	};
} &let {
	last             : bool = (id == 0x0000);
	# av_flags refinement
	constrained_auth : bool = (av_flags & 0x00000001) > 0 &if(id == 0x0006);
	mic_present      : bool = (av_flags & 0x00000002) > 0 &if(id == 0x0006);
	untrusted_source : bool = (av_flags & 0x00000004) > 0 &if(id == 0x0006);
};

type NTLM_Single_Host = record {
	size         : uint32;
	padpad       : padding[4];
	data_present : uint32;
	optional     : case custom_data_present of {
		true  -> custom_data : bytestring &length=4;
		false -> nothing     : empty;
	};
	machine_id   : uint32;
} &let {
	custom_data_present: bool = (data_present & 0x00000001) > 0;
};

type LM_Response(offset: uint16) = record {
	# This can be either LM (24 byte response) or
	# LMv2 (16 byte response + 8 byte client challenge. No way to
	# know for sure.
	padpad   : padding to offset;
	response : bytestring &length=24;
};

type NTLM_Response(offset: uint16) = record {
	padpad   : padding to offset;
	response : bytestring &length=24;
};

type NTLMv2_Response(flags: NTLM_Negotiate_Flags, offset: uint16) = record {
	padpad           : padding to offset;
	response         : bytestring &length=16;
	client_challenge : NTLMv2_Client_Challenge(flags);
};

type NTLMv2_Client_Challenge(flags: NTLM_Negotiate_Flags) = record {
	resp_type        : uint8;
	max_resp_type    : uint8;
	reserved         : padding[6];
	timestamp        : uint64;
	client_challenge : bytestring &length=8;
	reserved2        : padding[4];
	av_pairs         : NTLM_AV_Pair_Sequence(0);
};

type NTLM_Negotiate_Flags = record {
	flags: uint32;
} &let {
	negotiate_56                        : bool = (flags & 0x80000000) > 0;
	negotiate_key_exch                  : bool = (flags & 0x40000000) > 0;
	negotiate_128                       : bool = (flags & 0x20000000) > 0;

	negotiate_version                   : bool = (flags & 0x02000000) > 0;

	negotiate_target_info               : bool = (flags & 0x00800000) > 0;
	request_non_nt_session_key          : bool = (flags & 0x00400000) > 0;
	negotiate_identify                  : bool = (flags & 0x00100000) > 0;

	negotiate_extended_sessionsecurity  : bool = (flags & 0x00080000) > 0;
	target_type_server                  : bool = (flags & 0x00020000) > 0;
	target_type_domain                  : bool = (flags & 0x00010000) > 0;

	negotiate_always_sign               : bool = (flags & 0x00008000) > 0;
	negotiate_oem_workstation_supplied  : bool = (flags & 0x00002000) > 0;
	negotiate_oem_domain_supplied       : bool = (flags & 0x00001000) > 0;

	negotiate_anonymous_connection      : bool = (flags & 0x00000800) > 0;
	negotiate_ntlm                      : bool = (flags & 0x00000200) > 0;

	negotiate_lm_key                    : bool = (flags & 0x00000080) > 0;
	negotiate_datagram                  : bool = (flags & 0x00000040) > 0;
	negotiate_seal                      : bool = (flags & 0x00000020) > 0;
	negotiate_sign                      : bool = (flags & 0x00000010) > 0;

	request_target                      : bool = (flags & 0x00000004) > 0;
	negotiate_oem                       : bool = (flags & 0x00000002) > 0;
	negotiate_unicode                   : bool = (flags & 0x00000001) > 0;

	is_oem                              : bool = !negotiate_unicode && negotiate_oem;
	is_invalid                          : bool = !negotiate_unicode && !negotiate_oem;
};
