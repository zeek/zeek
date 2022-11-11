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
	SERVER_HELLO         -> server_hello         : ServerHelloChoice(rec);
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
type HelloRequest(rec: HandshakeRecord) = record {
	direction_check : DirectionCheck(false, rec); # should be sent by responder
};


######################################################################
# V3 Client Hello (7.4.1.2.)
######################################################################

type ClientHello(rec: HandshakeRecord) = record {
	direction_check : DirectionCheck(true, rec); # should be sent by originator
	client_version : uint16;
	gmt_unix_time : uint32;
	random_bytes : bytestring &length = 28;
	session_len : uint8;
	session_id : uint8[session_len];
	dtls_cookie: case client_version of {
		DTLSv10, DTLSv12 -> cookie: ClientHelloCookie(rec);
		default -> nothing: bytestring &length=0;
	};
	csuit_len : uint16; # &check(csuit_len > 1 && csuit_len % 2 == 0);
	csuits : uint16[csuit_len/2];
	cmeth_len : uint8; # &check(cmeth_len > 0);
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

# TLS 1.3 server hello is different from earlier versions. Trick around a
# bit, route 1.3 requests to a different record than earlier.
type ServerHelloChoice(rec: HandshakeRecord) = record {
	direction_check : DirectionCheck(false, rec); # should be sent by responder
	server_version0 : uint8;
	server_version1 : uint8;
	hello: case parsed_version of {
		TLSv13, TLSv13_draft -> hello13: ServerHello13(rec, server_version);
		default -> helloclassic: ServerHello(rec, server_version);
	} &requires(server_version) &requires(parsed_version);
} &let {
	server_version : uint16 = (server_version0 << 8) | server_version1;
	parsed_version : uint16 = case server_version0 of {
		0x7F -> 0x7F00; # map any draft version to 00
		default -> server_version;
	};
	version_set : bool = $context.connection.set_version(server_version);
};

type ServerHello(rec: HandshakeRecord, server_version: uint16) = record {
	random_bytes : bytestring &length = 32;
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

type ServerHello13(rec: HandshakeRecord, server_version: uint16) = record {
	random : bytestring &length = 32;
	cipher_suite : uint16[1];
	ext_len: uint16[] &until($element == 0 || $element != 0);
	extensions : SSLExtension(rec)[] &until($input.length() == 0);
} &let {
	cipher_set : bool =
		$context.connection.set_cipher(cipher_suite[0]);
};

# Used to check if originator/responder are reversed for this connection

type DirectionCheck(desired: bool, rec: HandshakeRecord) = record {
} &let {
	proc : bool = $context.connection.check_flipped(desired, rec.is_orig);
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

# The server key exchange contains the server public key exchange values, and a
# signature over those values for non-anonymous exchanges. The server key
# exchange messages is only sent for ECDHE, ECDH-anon, DHE, and DH-anon cipher
# suites.
type ServerKeyExchange(rec: HandshakeRecord) = case $context.connection.chosen_cipher() of {
	# ECDHE suites
	TLS_ECDHE_ECDSA_WITH_NULL_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_NULL_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
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
	TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
	TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
	TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		-> ecdhe_server_key_exchange : EcdheServerKeyExchange(rec);

	# ECDH-anon suites
	TLS_ECDH_ANON_WITH_NULL_SHA,
	TLS_ECDH_ANON_WITH_RC4_128_SHA,
	TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
	TLS_ECDH_ANON_WITH_AES_256_CBC_SHA
	# ECDH non-anon suites do not send a ServerKeyExchange
		-> ecdh_anon_server_key_exchange : EcdhAnonServerKeyExchange(rec);

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
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		-> dhe_server_key_exchange : DheServerKeyExchange(rec);

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
		-> dh_anon_server_key_exchange : DhAnonServerKeyExchange(rec);

	default
		-> key : bytestring &restofdata &transient;
};

# Parse an ECDHE ServerKeyExchange message, which contains a signature over the
# parameters. Parsing explicit curve parameters from the server is not
# currently supported.
type EcdheServerKeyExchange(rec: HandshakeRecord) = record {
	curve_type: uint8;
	named_curve: case curve_type of {
		NAMED_CURVE -> params: ServerECDHParamsAndSignature;
		default -> data: bytestring &restofdata &transient;
	};
	signature: case curve_type of {
		NAMED_CURVE -> signed_params: ServerKeyExchangeSignature;
		default -> nothing: bytestring &length=0;
	};
};

type ServerKeyExchangeSignature = record {
	alg: case uses_signature_and_hashalgorithm of {
		true -> algorithm: SignatureAndHashAlgorithm;
		false -> nothing: bytestring &length=0;
	} &requires(uses_signature_and_hashalgorithm);
	signature_length: uint16;
	signature: bytestring &length=signature_length;
} &let {
	uses_signature_and_hashalgorithm : bool =
		($context.connection.chosen_version() > TLSv11) &&
		($context.connection.chosen_version() != DTLSv10);
};

# Parse an ECDH-anon ServerKeyExchange message, which does not contain a
# signature over the parameters. Parsing explicit curve parameters from the
# server is not currently supported.
type EcdhAnonServerKeyExchange(rec: HandshakeRecord) = record {
	curve_type: uint8;
	named_curve: case curve_type of {
		NAMED_CURVE -> params: ServerECDHParamsAndSignature;
		default -> data: bytestring &restofdata &transient;
	};
};

type ServerECDHParamsAndSignature() = record {
	curve: uint16;
	point_length: uint8;
	point: bytestring &length=point_length;
};

# Parse a DHE ServerKeyExchange message, which contains a signature over the
# parameters.
type DheServerKeyExchange(rec: HandshakeRecord) = record {
	dh_p_length: uint16;
	dh_p: bytestring &length=dh_p_length;
	dh_g_length: uint16;
	dh_g: bytestring &length=dh_g_length;
	dh_Ys_length: uint16;
	dh_Ys: bytestring &length=dh_Ys_length;
	signed_params: ServerKeyExchangeSignature;
};

# Parse a DH-anon ServerKeyExchange message, which does not contain a
# signature over the parameters.
type DhAnonServerKeyExchange(rec: HandshakeRecord) = record {
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

# Parse a ClientKeyExchange message. For RSA cipher suites, this consists of an
# encrypted pre-master secret. For DH, DH-anon, and DHE cipher suites, this
# consists of the client public finite-field Diffie-Hellman value. For ECDH,
# ECDH-anon, and ECDHE cipher suites, this consists of the client public
# elliptic curve point.
type ClientKeyExchange(rec: HandshakeRecord) = case $context.connection.chosen_cipher() of {
	# RSA suites
	TLS_RSA_WITH_NULL_MD5,
	TLS_RSA_WITH_NULL_SHA,
	TLS_RSA_EXPORT_WITH_RC4_40_MD5,
	TLS_RSA_WITH_RC4_128_MD5,
	TLS_RSA_WITH_RC4_128_SHA,
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	TLS_RSA_WITH_IDEA_CBC_SHA,
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_RSA_WITH_DES_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_NULL_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
	TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
	TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_RMD,
	TLS_RSA_WITH_AES_128_CBC_RMD,
	TLS_RSA_WITH_AES_256_CBC_RMD,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_RSA_PSK_WITH_RC4_128_SHA,
	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_SEED_CBC_SHA,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
	TLS_RSA_PSK_WITH_NULL_SHA256,
	TLS_RSA_PSK_WITH_NULL_SHA384,
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_RSA_WITH_ARIA_128_CBC_SHA256,
	TLS_RSA_WITH_ARIA_256_CBC_SHA384,
	TLS_RSA_WITH_ARIA_128_GCM_SHA256,
	TLS_RSA_WITH_ARIA_256_GCM_SHA384,
	TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
	TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
	TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
	TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
	TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
	TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
	TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_RSA_WITH_AES_128_CCM,
	TLS_RSA_WITH_AES_256_CCM,
	TLS_RSA_WITH_AES_128_CCM_8,
	TLS_RSA_WITH_AES_256_CCM_8
		-> rsa_client_key_exchange: RsaClientKeyExchange(rec);

	#ECHDE
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
		-> ecdh_client_key_exchange : EcdhClientKeyExchange(rec);

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
		-> dh_server_key_exchange : DhClientKeyExchange(rec);

	default
		-> key : bytestring &restofdata &transient;
};

type RsaClientKeyExchange(rec: HandshakeRecord) = record {
	rsa_pms : bytestring &restofdata;
};

type DhClientKeyExchange(rec: HandshakeRecord) = record {
	dh_Yc : bytestring &restofdata;
};

type EcdhClientKeyExchange(rec: HandshakeRecord) = record {
	point : bytestring &restofdata;
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
		EXT_SIGNATURE_ALGORITHMS -> signature_algorithm: SignatureAlgorithm(rec)[] &until($element == 0 || $element != 0);
		EXT_SIGNED_CERTIFICATE_TIMESTAMP -> certificate_timestamp: SignedCertificateTimestampList(rec)[] &until($element == 0 || $element != 0);
		EXT_KEY_SHARE -> key_share: KeyShare(rec, this)[] &until($element == 0 || $element != 0);
		EXT_KEY_SHARE_OLD -> key_share_old: KeyShare(rec, this)[] &until($element == 0 || $element != 0);
		EXT_SUPPORTED_VERSIONS -> supported_versions_selector: SupportedVersionsSelector(rec, data_len)[] &until($element == 0 || $element != 0);
		EXT_PSK_KEY_EXCHANGE_MODES -> psk_key_exchange_modes: PSKKeyExchangeModes(rec)[] &until($element == 0 || $element != 0);
		EXT_PRE_SHARED_KEY -> pre_shared_key: PreSharedKey(rec)[] &until($element == 0 || $element != 0);
		default -> data: bytestring &restofdata;
	};
} &length=data_len+4 &exportsourcedata;

%include tls-handshake-signed_certificate_timestamp.pac

type SupportedVersionsSelector(rec: HandshakeRecord, data_len: uint16) = case ( rec.is_orig ^ $context.connection.flipped() ) of {
	true -> a: SupportedVersions(rec);
	false -> b: OneSupportedVersion(rec);
}

type SupportedVersions(rec: HandshakeRecord) = record {
	length: uint8;
	versions: uint16[] &until($input.length() == 0);
} &length=length+1;

# If the server sends it, this is the authoritative version. Set it.
type OneSupportedVersion(rec: HandshakeRecord) = record {
	version: uint16;
} &let {
	version_set : bool = $context.connection.set_version(version);
};


type PSKKeyExchangeModes(rec: HandshakeRecord) = record {
	length: uint8;
	modes: uint8[] &until($input.length() == 0);
} &length=length+1;

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

type KeyShareEntry() = record {
	namedgroup : uint16;
	key_exchange_length : uint16;
	key_exchange: bytestring &length=key_exchange_length &transient;
};

type ServerHelloKeyShare(rec: HandshakeRecord) = record {
	keyshare : KeyShareEntry;
};

type HelloRetryRequestKeyShare(rec: HandshakeRecord) = record {
	namedgroup : uint16;
};

type ServerHelloKeyShareChoice(rec: HandshakeRecord, ext: SSLExtension) = case (ext.data_len) of {
	2 -> hrr : HelloRetryRequestKeyShare(rec);
	default -> server : ServerHelloKeyShare(rec);
};

type ClientHelloKeyShare(rec: HandshakeRecord) = record {
	length: uint16;
	keyshares : KeyShareEntry[] &until($input.length() == 0);
} &length=(length+2);

type KeyShare(rec: HandshakeRecord, ext: SSLExtension) = case rec.msg_type of {
	CLIENT_HELLO -> client_hello_keyshare : ClientHelloKeyShare(rec);
	SERVER_HELLO -> server_hello_keyshare : ServerHelloKeyShareChoice(rec, ext);
	# in old traces, theoretically hello retry requests might show up as a separate type here.
	# If this happens, just ignore the extension - we do not have any example traffic for this.
	# And it will not happen in anything speaking TLS 1.3, or not completely ancient drafts of it.
	default -> other : bytestring &restofdata &transient;
};

type SelectedPreSharedKeyIdentity(rec: HandshakeRecord) = record {
	selected_identity: uint16;
};

type PSKIdentity() = record {
	length: uint16;
	identity: bytestring &length=length;
	obfuscated_ticket_age: uint32;
};

type PSKIdentitiesList() = record {
	length: uint16;
	identities: PSKIdentity[] &until($input.length() == 0);
} &length=length+2;

type PSKBinder() = record {
	length: uint8;
	binder: bytestring &length=length;
};

type PSKBindersList() = record {
	length: uint16;
	binders: PSKBinder[] &until($input.length() == 0);
} &length=length+2;

type OfferedPsks(rec: HandshakeRecord) = record {
	identities: PSKIdentitiesList;
	binders: PSKBindersList;
};

type PreSharedKey(rec: HandshakeRecord) = case rec.msg_type of {
	CLIENT_HELLO -> offered_psks : OfferedPsks(rec);
	SERVER_HELLO -> selected_identity : SelectedPreSharedKeyIdentity(rec);
	# ... well, we don't parse hello retry requests yet, because I don't have an example of them on the wire.
	default -> other : bytestring &restofdata &transient;
};

type SignatureAlgorithm(rec: HandshakeRecord) = record {
	length: uint16;
	supported_signature_algorithms: SignatureAndHashAlgorithm[] &until($input.length() == 0);
}

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
		uint16 chosen_version_;
		uint16 record_version_;
		bytestring client_random_;
		bytestring server_random_;
		uint32 gmt_unix_time_;
		bool flipped_;
		bool already_alerted_;
	%}

	%init{
		flipped_ = false;
		already_alerted_ = false;
		chosen_cipher_ = NO_CHOSEN_CIPHER;
		chosen_version_ = UNKNOWN_VERSION;

		record_version_ = 0;
		gmt_unix_time_ = 0;
	%}

	%cleanup{
		client_random_.free();
		server_random_.free();
	%}

	function chosen_cipher() : int %{ return chosen_cipher_; %}

	function set_cipher(cipher: uint32) : bool
		%{
		chosen_cipher_ = cipher;
		return true;
		%}

	function chosen_version() : uint16 %{ return chosen_version_; %}

	# This function is called several times in certain circumstances.
	# If it is called twice, it is first called due to the supported_versions
	# field in the server hello - and then again due to the outer version in
	# the server hello. So - once we have a version here, let's just stick
	# with it.
	function set_version(version: uint16) : bool
		%{
		if ( chosen_version_ != UNKNOWN_VERSION )
			return false;

		chosen_version_ = version;
		return true;
		%}

	function check_flipped(desired: bool, is_orig: bool) : bool
		%{
		if ( flipped_ )
			{
			if ( desired == is_orig )
				{
				// well, I guess we get to flip it back - and alert on this
				flipped_ = false;
				zeek::BifEvent::enqueue_ssl_connection_flipped(zeek_analyzer(), zeek_analyzer()->Conn());
				if ( ! already_alerted_ )
					{
					already_alerted_ = true;
					zeek_analyzer()->Weird("SSL_unclear_connection_direction");
					}
				}
			}
			else
			{
			if ( desired != is_orig )
				{
				flipped_ = true;
				zeek::BifEvent::enqueue_ssl_connection_flipped(zeek_analyzer(), zeek_analyzer()->Conn());
				}
			}

		return true;
		%}

	function flipped() : bool
		%{
		return flipped_;
		%}

	function record_version() : uint16 %{ return record_version_; %}

	function set_record_version(version: uint16) : bool
		%{
		record_version_ = version;
		return true;
		%}

	function client_random() : bytestring %{ return client_random_; %}

	function set_client_random(client_random: bytestring) : bool
		%{
		client_random_.free();
		client_random_.init(client_random.data(), client_random.length());
		return true;
		%}

	function server_random() : bytestring %{ return server_random_; %}

	function set_server_random(server_random: bytestring) : bool
		%{
		server_random_.free();
		server_random_.init(server_random.data(), server_random.length());
		return true;
		%}

	function gmt_unix_time() : uint32 %{ return gmt_unix_time_; %}

	function set_gmt_unix_time(ts: uint32) : bool
		%{
		gmt_unix_time_ = ts;
		return true;
		%}
};

