
type GSSAPI_NEG_TOKEN(is_orig: bool) = record {
	wrapper  : ASN1EncodingMeta;
	have_oid : case is_init of {
		true  -> oid    : ASN1Encoding;
		false -> no_oid : empty;
	};
	have_init_wrapper : case is_init of {
		true  -> init_wrapper    : ASN1EncodingMeta;
		false -> no_init_wrapper : empty;
	};
	msg_type : case is_init of {
		true  -> init : GSSAPI_NEG_TOKEN_INIT;
		false -> resp : GSSAPI_NEG_TOKEN_RESP;
	};
} &let {
	is_init: bool = wrapper.tag == 0x60;
} &byteorder=littleendian;

type GSSAPI_NEG_TOKEN_INIT = record {
	seq_meta : ASN1EncodingMeta;
	args     : GSSAPI_NEG_TOKEN_INIT_Arg[];
};

type GSSAPI_NEG_TOKEN_INIT_Arg = record {
	seq_meta : ASN1EncodingMeta;
	args     : GSSAPI_NEG_TOKEN_INIT_Arg_Data(seq_meta.index) &length=seq_meta.length;
};

type GSSAPI_NEG_TOKEN_INIT_Arg_Data(index: uint8) = case index of {
	0 -> mech_type_list : ASN1Encoding;
	1 -> req_flags      : ASN1Encoding;
	2 -> mech_token     : GSSAPI_NEG_TOKEN_MECH_TOKEN(true);
	3 -> mech_list_mic  : ASN1OctetString;
};

type GSSAPI_NEG_TOKEN_RESP = record {
	seq_meta : ASN1EncodingMeta;
	args     : GSSAPI_NEG_TOKEN_RESP_Arg[];
};

type GSSAPI_NEG_TOKEN_RESP_Arg = record {
	seq_meta : ASN1EncodingMeta;
	args     : case seq_meta.index of {
		0       -> neg_state      : ASN1Integer;
		1       -> supported_mech : ASN1Encoding;
		2       -> response_token : GSSAPI_NEG_TOKEN_MECH_TOKEN(false);
		3       -> mech_list_mic  : ASN1OctetString;
	} &length=seq_meta.length;
};

type GSSAPI_NEG_TOKEN_MECH_TOKEN(is_orig: bool) = record {
	meta  : ASN1EncodingMeta;
	token : bytestring &length=meta.length;
} &let {
	ntlm : bytestring withinput token &if($context.connection.is_first_byte(token, 0x4E)) &restofdata;
	krb : KRB_BLOB withinput token &if($context.connection.is_first_byte(token, 0x60)) &restofdata;
};

type KRB_BLOB = record {
	meta     : ASN1EncodingMeta;
	oid      : ASN1OctetString;
	token_id : uint16 &byteorder=littleendian;
	blob     : bytestring &restofdata;
};

refine connection GSSAPI_Conn += {
	function is_first_byte(token: bytestring, byte: uint8): bool
		%{
		return token[0] == byte;
		%}
};
