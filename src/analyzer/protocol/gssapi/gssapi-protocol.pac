enum GSSAPI_Token_Type {
	GSSAPI_SPNEGO_INIT = 0,
	GSSAPI_SPNEGO_RESP = 1,
	GSSAPI_KRB5        = 2,
};

type GSSAPI_SELECT(is_orig: bool) = record {
	wrapper  : ASN1EncodingMeta;
	token: case tok_id of {
		0x0404 -> mic_blob: bytestring &restofdata;
		0x0504 -> wrap_blob: bytestring &restofdata;
		default -> neg_token: GSSAPI_NEG_TOKEN(is_orig, is_init);
	} &requires(is_init) &requires(tok_id);
} &let {
	is_init: bool = wrapper.tag == 0x60;
	tok_id: uint32 = (wrapper.tag << 8) | wrapper.len;
} &byteorder=littleendian;

type GSSAPI_NEG_TOKEN(is_orig: bool, is_init: bool) = record {
	have_oid : case is_init of {
		true  -> oid    : ASN1Encoding;
		false -> no_oid : empty;
	};
	have_init_wrapper : case token_type of {
		GSSAPI_SPNEGO_INIT -> init_wrapper    : ASN1EncodingMeta;
		default            -> no_init_wrapper : empty;
	} &requires(token_type);
	msg_type : case token_type of {
		GSSAPI_SPNEGO_INIT -> init : GSSAPI_NEG_TOKEN_INIT;
		GSSAPI_SPNEGO_RESP -> resp : GSSAPI_NEG_TOKEN_RESP;
		GSSAPI_KRB5        -> krb5 : GSSAPI_KRB5_TOKEN;
	};
} &let {
	# The OID selects the inner token: SPNEGO or Kerberos 5 (RFC 2743 section 3.1).
	token_type: uint8 = ! is_init ? GSSAPI_SPNEGO_RESP :
		($context.connection.is_krb5_oid(oid.content) ? GSSAPI_KRB5 : GSSAPI_SPNEGO_INIT);
} &byteorder=littleendian;

# Krb 5 context establishment token (RFC 4121 section 4.1)
type GSSAPI_KRB5_TOKEN = record {
	token_id : uint16 &byteorder=bigendian;
	blob     : bytestring &restofdata;
};

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
	krb_with_oid : KRB_OID_BLOB withinput token &if($context.connection.is_first_byte(token, 0x60)) &restofdata;
	krb_blob : bytestring withinput token &if(context.connection.is_first_byte(token, 0x6E) || context.connection.is_first_byte(token, 0x6F)) &restofdata;
};

type KRB_OID_BLOB = record {
	meta     : ASN1EncodingMeta;
	oid      : ASN1OctetString;
	token_id : uint16 &byteorder=littleendian;
	blob     : bytestring &restofdata;
};

refine connection GSSAPI_Conn += {
	function is_first_byte(token: bytestring, byte: uint8): bool
		%{
		return token.length() > 0 && token[0] == byte;
		%}

	function is_krb5_oid(oid: bytestring): bool
		%{
		// 1.2.840.113554.1.2.2 (RFC 1964 section 1) and 1.2.840.48018.1.2.2 (MS Kerberos 5)
		static const uint8 krb5[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
		static const uint8 ms_krb5[] = { 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02 };

		return oid.length() == sizeof(krb5) &&
		       ( memcmp(oid.begin(), krb5, sizeof(krb5)) == 0 ||
		         memcmp(oid.begin(), ms_krb5, sizeof(ms_krb5)) == 0 );
		%}
};
