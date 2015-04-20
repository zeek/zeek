######################################################################
# Handshake Protocols (7.)
######################################################################

enum HandshakeType {
	HELLO_REQUEST       = 0,
	CLIENT_HELLO        = 1,
	SERVER_HELLO        = 2,
	HELLO_VERIFY_REQUEST = 3, # DTLS
	SESSION_TICKET      = 4, # RFC 5077
	CERTIFICATE         = 11,
	SERVER_KEY_EXCHANGE = 12,
	CERTIFICATE_REQUEST = 13,
	SERVER_HELLO_DONE   = 14,
	CERTIFICATE_VERIFY  = 15,
	CLIENT_KEY_EXCHANGE = 16,
	FINISHED            = 20,
	CERTIFICATE_URL     = 21, # RFC 3546
	CERTIFICATE_STATUS  = 22, # RFC 3546
};


######################################################################
# V3 Handshake Protocol (7.)
######################################################################

type HandshakeRecord(is_orig: bool) = record {
  msg_type: uint8;
	msg_length: uint24;
	rec: Handshake(this);
} &length=(to_int()(msg_length) + 4);

type Handshake(rec: HandshakeRecord) = case rec.msg_type of {
	HELLO_REQUEST        -> hello_request        : HelloRequest(rec);
	CLIENT_HELLO         -> client_hello         : ClientHello(rec);
	SERVER_HELLO         -> server_hello         : ServerHello(rec);
	HELLO_VERIFY_REQUEST -> hello_verify_request : HelloVerifyRequest(rec);
	SESSION_TICKET       -> session_ticket       : SessionTicketHandshake(rec);
	CERTIFICATE          -> certificate          : Certificate(rec);
	SERVER_KEY_EXCHANGE  -> server_key_exchange  : ServerKeyExchange(rec);
	CERTIFICATE_REQUEST  -> certificate_request  : CertificateRequest(rec);
	SERVER_HELLO_DONE    -> server_hello_done    : ServerHelloDone(rec);
	CERTIFICATE_VERIFY   -> certificate_verify   : CertificateVerify(rec);
	CLIENT_KEY_EXCHANGE  -> client_key_exchange  : ClientKeyExchange(rec);
	FINISHED             -> finished             : Finished(rec);
	CERTIFICATE_URL      -> certificate_url      : bytestring &restofdata &transient;
	CERTIFICATE_STATUS   -> certificate_status   : CertificateStatus(rec);
	default              -> unknown_handshake    : UnknownHandshake(rec, rec.is_orig);
}

type HandshakePDU(is_orig: bool) = record {
	records: HandshakeRecord(is_orig)[] &transient;
} &byteorder = bigendian;

type UnknownHandshake(hs: HandshakeRecord, is_orig: bool) = record {
	data : bytestring &restofdata &transient;
};

######################################################################
# V3 Hello Request (7.4.1.1.)
######################################################################

# Hello Request is empty
type HelloRequest(rec: HandshakeRecord) = empty;


######################################################################
# V3 Client Hello (7.4.1.2.)
######################################################################

type ClientHello(rec: HandshakeRecord) = record {
	client_version : uint16;
	gmt_unix_time : uint32;
	random_bytes : bytestring &length = 28;
	session_len : uint8;
	session_id : uint8[session_len];
	dtls_cookie: case client_version of {
		DTLSv10 -> cookie: ClientHelloCookie(rec);
		default -> nothing: bytestring &length=0;
	};
	csuit_len : uint16 &check(csuit_len > 1 && csuit_len % 2 == 0);
	csuits : uint16[csuit_len/2];
	cmeth_len : uint8 &check(cmeth_len > 0);
	cmeths : uint8[cmeth_len];
	# This weirdness is to deal with the possible existence or absence
	# of the following fields.
	ext_len: uint16[] &until($element == 0 || $element != 0);
	extensions : SSLExtension(rec)[] &until($input.length() == 0);
};

type ClientHelloCookie(rec: HandshakeRecord) = record {
	cookie_len : uint8;
	cookie : bytestring &length = cookie_len;
};

######################################################################
# V3 Server Hello (7.4.1.3.)
######################################################################

type ServerHello(rec: HandshakeRecord) = record {
	server_version : uint16;
	gmt_unix_time : uint32;
	random_bytes : bytestring &length = 28;
	session_len : uint8;
	session_id : uint8[session_len];
	cipher_suite : uint16[1];
	compression_method : uint8;
	# This weirdness is to deal with the possible existence or absence
	# of the following fields.
	ext_len: uint16[] &until($element == 0 || $element != 0);
	extensions : SSLExtension(rec)[] &until($input.length() == 0);
} &let {
	cipher_set : bool =
		$context.connection.set_cipher(cipher_suite[0]);
};

######################################################################
# DTLS Hello Verify Request
######################################################################

type HelloVerifyRequest(rec: HandshakeRecord) = record {
	version: uint16;
	cookie_length: uint8;
	cookie: bytestring &length=cookie_length;
};

######################################################################
# V3 Server Certificate (7.4.2.)
######################################################################

type X509Certificate = record {
	length : uint24;
	certificate : bytestring &length = to_int()(length);
};

type Certificate(rec: HandshakeRecord) = record {
	length : uint24;
	certificates : X509Certificate[] &until($input.length() == 0);
} &length = to_int()(length)+3;

# OCSP Stapling

type CertificateStatus(rec: HandshakeRecord) = record {
	status_type: uint8; # 1 = ocsp, everything else is undefined
	length : uint24;
	response: bytestring &restofdata;
};

######################################################################
# V3 Server Key Exchange Message (7.4.3.)
######################################################################

# Usually, the server key exchange does not contain any information
# that we are interested in.
#
# The exception is when we are using an ECDHE, DHE or DH-Anon suite.
# In this case, we can extract information about the chosen cipher from
# here.
type ServerKeyExchange(rec: HandshakeRecord) = case $context.connection.chosen_cipher() of {
	TLS_ECDH_ECDSA_WITH_NULL_SHA,
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_NULL_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_RSA_WITH_NULL_SHA,
	TLS_ECDH_RSA_WITH_RC4_128_SHA,
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_NULL_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_ANON_WITH_NULL_SHA,
	TLS_ECDH_ANON_WITH_RC4_128_SHA,
	TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
	TLS_ECDH_ANON_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_PSK_WITH_RC4_128_SHA,
	TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_PSK_WITH_NULL_SHA,
	TLS_ECDHE_PSK_WITH_NULL_SHA256,
	TLS_ECDHE_PSK_WITH_NULL_SHA384,
	TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
	TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
	TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
	TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
	TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
	TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
	TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
	TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
	TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
	TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
	TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		-> ec_server_key_exchange : EcServerKeyExchange(rec);

	# DHE suites
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_DSS_WITH_DES_CBC_SHA,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_RSA_WITH_DES_CBC_SHA,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
	TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
	TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
	TLS_DHE_DSS_WITH_RC4_128_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD,
	TLS_DHE_DSS_WITH_AES_128_CBC_RMD,
	TLS_DHE_DSS_WITH_AES_256_CBC_RMD,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD,
	TLS_DHE_RSA_WITH_AES_128_CBC_RMD,
	TLS_DHE_RSA_WITH_AES_256_CBC_RMD,
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DHE_PSK_WITH_RC4_128_SHA,
	TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
	TLS_DHE_DSS_WITH_SEED_CBC_SHA,
	TLS_DHE_RSA_WITH_SEED_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
	TLS_DHE_PSK_WITH_NULL_SHA256,
	TLS_DHE_PSK_WITH_NULL_SHA384,
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
	TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
	TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
	TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
	TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
	TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
	TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
	TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
	TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
	TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
	TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
	TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
	TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_DHE_RSA_WITH_AES_128_CCM,
	TLS_DHE_RSA_WITH_AES_256_CCM,
	TLS_DHE_RSA_WITH_AES_128_CCM_8,
	TLS_DHE_RSA_WITH_AES_256_CCM_8,
	TLS_DHE_PSK_WITH_AES_128_CCM,
	TLS_DHE_PSK_WITH_AES_256_CCM,
	TLS_PSK_DHE_WITH_AES_128_CCM_8,
	TLS_PSK_DHE_WITH_AES_256_CCM_8,
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	# DH-anon suites
	TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5,
	TLS_DH_ANON_WITH_RC4_128_MD5,
	TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_ANON_WITH_DES_CBC_SHA,
	TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA,
	TLS_DH_ANON_WITH_AES_128_CBC_SHA,
	TLS_DH_ANON_WITH_AES_256_CBC_SHA,
	TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA,
	TLS_DH_ANON_WITH_AES_128_CBC_SHA256,
	TLS_DH_ANON_WITH_AES_256_CBC_SHA256,
	TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DH_ANON_WITH_SEED_CBC_SHA,
	TLS_DH_ANON_WITH_AES_128_GCM_SHA256,
	TLS_DH_ANON_WITH_AES_256_GCM_SHA384,
	TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256,
	TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384,
	TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256,
	TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384,
	TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384
	# DH non-anon suites do not send a ServerKeyExchange
		-> dh_server_key_exchange : DhServerKeyExchange(rec);

	default
		-> key : bytestring &restofdata &transient;
};

# For the moment, we really only are interested in the curve name. If it
# is not set (if the server sends explicit parameters), we do not bother.
# We also do not parse the actual signature data following the named curve.
type EcServerKeyExchange(rec: HandshakeRecord) = record {
	curve_type: uint8;
	curve: uint16; # only if curve_type = 3 (NAMED_CURVE)
	data: bytestring &restofdata &transient;
};

# For both, dh_anon and dhe the ServerKeyExchange starts with a ServerDHParams
# structure. After that, they start to differ, but we do not care about that.
type DhServerKeyExchange(rec: HandshakeRecord) = record {
	dh_p_length: uint16;
	dh_p: bytestring &length=dh_p_length;
	dh_g_length: uint16;
	dh_g: bytestring &length=dh_g_length;
	dh_Ys_length: uint16;
	dh_Ys: bytestring &length=dh_Ys_length;
	data: bytestring &restofdata &transient;
};


######################################################################
# V3 Certificate Request (7.4.4.)
######################################################################

# For now, ignore Certificate Request Details; just eat up message.
type CertificateRequest(rec: HandshakeRecord) = record {
	cont : bytestring &restofdata &transient;
};


######################################################################
# V3 Server Hello Done (7.4.5.)
######################################################################

# Server Hello Done is empty
type ServerHelloDone(rec: HandshakeRecord) = empty;


######################################################################
# V3 Client Certificate (7.4.6.)
######################################################################

# Client Certificate is identical to Server Certificate;
# no further definition here


######################################################################
# V3 Client Key Exchange Message (7.4.7.)
######################################################################

# For now ignore details of ClientKeyExchange (most of it is
# encrypted anyway); just eat up message.
type ClientKeyExchange(rec: HandshakeRecord) = record {
	key : bytestring &restofdata &transient;
};


######################################################################
# V3 Certificate Verify (7.4.8.)
######################################################################

# For now, ignore Certificate Verify; just eat up the message.
type CertificateVerify(rec: HandshakeRecord) = record {
	cont : bytestring &restofdata &transient;
};


######################################################################
# V3 Finished (7.4.9.)
######################################################################

# The finished messages are always sent after encryption is in effect,
# so we will not be able to read those messages.
type Finished(rec: HandshakeRecord) = record {
	cont : bytestring &restofdata &transient;
};

type SessionTicketHandshake(rec: HandshakeRecord) = record {
	ticket_lifetime_hint: uint32;
	data:                 bytestring &restofdata;
};

######################################################################
# TLS Extensions
######################################################################

type SSLExtension(rec: HandshakeRecord) = record {
	type: uint16;
	data_len: uint16;

	# Pretty code ahead. Deal with the fact that perhaps extensions are
	# not really present and we do not want to fail because of that.
	ext: case type of {
		EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION -> apnl: ApplicationLayerProtocolNegotiationExtension(rec)[] &until($element == 0 || $element != 0);
		EXT_ELLIPTIC_CURVES -> elliptic_curves: EllipticCurves(rec)[] &until($element == 0 || $element != 0);
		EXT_EC_POINT_FORMATS -> ec_point_formats: EcPointFormats(rec)[] &until($element == 0 || $element != 0);
#		EXT_STATUS_REQUEST -> status_request: StatusRequest(rec)[] &until($element == 0 || $element != 0);
		EXT_SERVER_NAME -> server_name: ServerNameExt(rec)[] &until($element == 0 || $element != 0);
		default -> data: bytestring &restofdata;
	};
} &length=data_len+4 &exportsourcedata;

type ServerNameHostName() = record {
	length: uint16;
	host_name: bytestring &length=length;
};

type ServerName() = record {
	name_type: uint8; # has to be 0 for host-name
	name: case name_type of {
		0 -> host_name: ServerNameHostName;
		default -> data : bytestring &restofdata &transient; # unknown name
	};
};

type ServerNameExt(rec: HandshakeRecord) = record {
	length: uint16;
	server_names: ServerName[] &until($input.length() == 0);
} &length=length+2;

# Do not parse for now. Structure is correct, but only contains asn.1 data that we would not use further.
#type OcspStatusRequest(rec: HandshakeRecord) = record {
#	responder_id_list_length: uint16;
#	responder_id_list: bytestring &length=responder_id_list_length;
#	request_extensions_length: uint16;
#	request_extensions: bytestring &length=request_extensions_length;
#};
#
#type StatusRequest(rec: HandshakeRecord) = record {
#	status_type: uint8; # 1 -> ocsp
#	req: case status_type of {
#		1 -> ocsp_status_request: OcspStatusRequest(rec);
#		default -> data : bytestring &restofdata &transient; # unknown
#	};
#};

type EcPointFormats(rec: HandshakeRecord) = record {
	length: uint8;
	point_format_list: uint8[length];
};

type EllipticCurves(rec: HandshakeRecord) = record {
	length: uint16;
	elliptic_curve_list: uint16[length/2];
};

type ProtocolName() = record {
  length: uint8;
	name: bytestring &length=length;
};

type ApplicationLayerProtocolNegotiationExtension(rec: HandshakeRecord) = record {
	length: uint16;
	protocol_name_list: ProtocolName[] &until($input.length() == 0);
} &length=length+2;

refine connection Handshake_Conn += {

	%member{
		uint32 chosen_cipher_;
	%}

	%init{
		chosen_cipher_ = NO_CHOSEN_CIPHER;
	%}

	function chosen_cipher() : int %{ return chosen_cipher_; %}

	function set_cipher(cipher: uint32) : bool
		%{
		chosen_cipher_ = cipher;
		return true;
		%}
};


