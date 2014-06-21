# Analyzer for SSL messages (general part).
# To be used in conjunction with an SSL record-layer analyzer.
# Separation is necessary due to possible fragmentation of SSL records.

######################################################################
# General definitions
######################################################################

type uint24 = record {
	byte1 : uint8;
	byte2 : uint8;
	byte3 : uint8;
};

%header{
	class to_int {
	public:
		int operator()(uint24 * num) const
		{
		return (num->byte1() << 16) | (num->byte2() << 8) | num->byte3();
		}
	};

	string state_label(int state_nr);
%}

extern type to_int;

type SSLRecord(is_orig: bool) = record {
	head0 : uint8;
	head1 : uint8;
	head2 : uint8;
	head3 : uint8;
	head4 : uint8;
	rec : RecordText(this)[] &length=length, &requires(content_type);
} &length = length+5, &byteorder=bigendian,
	&let {
	version : int =
		$context.connection.determine_ssl_record_layer(head0, head1, head2, head3, head4);

	content_type : int = case version of {
		SSLv20 -> head2+300;
		default -> head0;
	};

	length : int = case version of {
		# fail analyzer if the packet cannot be recognized as TLS.
		UNKNOWN_VERSION -> 0;
		SSLv20 -> (((head0 & 0x7f) << 8) | head1) - 3;
		default -> (head3 << 8) | head4;
	};
};

type RecordText(rec: SSLRecord) = case $context.connection.state(rec.is_orig) of {
	STATE_ENCRYPTED
		-> ciphertext : CiphertextRecord(rec);
	default
		-> plaintext : PlaintextRecord(rec);
};

type PlaintextRecord(rec: SSLRecord) = case rec.content_type of {
	CHANGE_CIPHER_SPEC	-> ch_cipher : ChangeCipherSpec(rec);
	ALERT			-> alert : Alert(rec);
	HANDSHAKE		-> handshake : Handshake(rec);
	HEARTBEAT -> heartbeat: Heartbeat(rec);
	APPLICATION_DATA	-> app_data : ApplicationData(rec);
	V2_ERROR		-> v2_error : V2Error(rec);
	V2_CLIENT_HELLO		-> v2_client_hello : V2ClientHello(rec);
	V2_CLIENT_MASTER_KEY	-> v2_client_master_key : V2ClientMasterKey(rec);
	V2_SERVER_HELLO		-> v2_server_hello : V2ServerHello(rec);
	default			-> unknown_record : UnknownRecord(rec);
};

######################################################################
# TLS Extensions
######################################################################

type SSLExtension(rec: SSLRecord) = record {
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

type ServerNameExt(rec: SSLRecord) = record {
	length: uint16;
	server_names: ServerName[] &until($input.length() == 0);
} &length=length+2;

# Do not parse for now. Structure is correct, but only contains asn.1 data that we would not use further.
#type OcspStatusRequest(rec: SSLRecord) = record {
#	responder_id_list_length: uint16;
#	responder_id_list: bytestring &length=responder_id_list_length;
#	request_extensions_length: uint16;
#	request_extensions: bytestring &length=request_extensions_length;
#};
#
#type StatusRequest(rec: SSLRecord) = record {
#	status_type: uint8; # 1 -> ocsp
#	req: case status_type of {
#		1 -> ocsp_status_request: OcspStatusRequest(rec);
#		default -> data : bytestring &restofdata &transient; # unknown
#	};
#};

type EcPointFormats(rec: SSLRecord) = record {
	length: uint8;
	point_format_list: uint8[length];
};

type EllipticCurves(rec: SSLRecord) = record {
	length: uint16;
	elliptic_curve_list: uint16[length/2];
};

type ProtocolName() = record {
  length: uint8;
	name: bytestring &length=length;
};

type ApplicationLayerProtocolNegotiationExtension(rec: SSLRecord) = record {
	length: uint16;
	protocol_name_list: ProtocolName[] &until($input.length() == 0);
} &length=length+2;

######################################################################
# Encryption Tracking
######################################################################

enum AnalyzerState {
	STATE_CLEAR,
	STATE_ENCRYPTED
};

%code{
	string state_label(int state_nr)
		{
		switch ( state_nr ) {
		case STATE_CLEAR:
			return string("CLEAR");

		case STATE_ENCRYPTED:
			return string("ENCRYPTED");

		default:
			return string(fmt("UNKNOWN (%d)", state_nr));
		}
		}
%}

######################################################################
# SSLv3 Handshake Protocols (7.)
######################################################################

enum HandshakeType {
	HELLO_REQUEST       = 0,
	CLIENT_HELLO        = 1,
	SERVER_HELLO        = 2,
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
# V3 Change Cipher Spec Protocol (7.1.)
######################################################################

type ChangeCipherSpec(rec: SSLRecord) = record {
	type : uint8;
} &length = 1, &let {
	state_changed : bool =
		$context.connection.startEncryption(rec.is_orig);
};


######################################################################
# V3 Alert Protocol (7.2.)
######################################################################

type Alert(rec: SSLRecord) = record {
	level : uint8;
	description: uint8;
};


######################################################################
# V2 Error Records (SSLv2 2.7.)
######################################################################

type V2Error(rec: SSLRecord) = record {
	data : bytestring &restofdata &transient;
} &let {
	error_code : uint16 = ((rec.head3 << 8) | rec.head4);
};


######################################################################
# V3 Application Data
######################################################################

# Application data should always be encrypted, so we should not
# reach this point.
type ApplicationData(rec: SSLRecord) = record {
	data : bytestring &restofdata &transient;
};

######################################################################
# V3 Heartbeat
######################################################################

type Heartbeat(rec: SSLRecord) = record {
	type : uint8;
	payload_length : uint16;
	data : bytestring &restofdata;
};

######################################################################
# V3 Hello Request (7.4.1.1.)
######################################################################

# Hello Request is empty
type HelloRequest(rec: SSLRecord) = empty;


######################################################################
# V3 Client Hello (7.4.1.2.)
######################################################################

type ClientHello(rec: SSLRecord) = record {
	client_version : uint16;
	gmt_unix_time : uint32;
	random_bytes : bytestring &length = 28;
	session_len : uint8;
	session_id : uint8[session_len];
	csuit_len : uint16 &check(csuit_len > 1 && csuit_len % 2 == 0);
	csuits : uint16[csuit_len/2];
	cmeth_len : uint8 &check(cmeth_len > 0);
	cmeths : uint8[cmeth_len];
	# This weirdness is to deal with the possible existence or absence
	# of the following fields.
	ext_len: uint16[] &until($element == 0 || $element != 0);
	extensions : SSLExtension(rec)[] &until($input.length() == 0);
};

######################################################################
# V2 Client Hello (SSLv2 2.5.)
######################################################################

type V2ClientHello(rec: SSLRecord) = record {
	csuit_len : uint16;
	session_len : uint16;
	chal_len : uint16;
	ciphers : uint24[csuit_len/3];
	session_id : uint8[session_len];
	challenge : bytestring &length = chal_len;
} &length = 6 + csuit_len + session_len + chal_len, &let {
	client_version : int = rec.version;
};


######################################################################
# V3 Server Hello (7.4.1.3.)
######################################################################

type ServerHello(rec: SSLRecord) = record {
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
# V2 Server Hello (SSLv2 2.6.)
######################################################################

type V2ServerHello(rec: SSLRecord) = record {
	#session_id_hit : uint8;
	#cert_type : uint8;
	server_version : uint16;
	cert_len : uint16;
	ciph_len : uint16;
	conn_id_len : uint16;
	cert_data : bytestring &length = cert_len;
	ciphers : uint24[ciph_len/3];
	conn_id_data : bytestring &length = conn_id_len;
} &let {
	session_id_hit : uint8 = rec.head3;
	cert_type : uint8 = rec.head4;
};


######################################################################
# V3 Server Certificate (7.4.2.)
######################################################################

type X509Certificate = record {
	length : uint24;
	certificate : bytestring &length = to_int()(length);
};

type Certificate(rec: SSLRecord) = record {
	length : uint24;
	certificates : X509Certificate[] &until($input.length() == 0);
} &length = to_int()(length)+3;

# OCSP Stapling

type CertificateStatus(rec: SSLRecord) = record {
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
type ServerKeyExchange(rec: SSLRecord) = case $context.connection.chosen_cipher() of {
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
type EcServerKeyExchange(rec: SSLRecord) = record {
	curve_type: uint8;
	curve: uint16; # only if curve_type = 3 (NAMED_CURVE)
	data: bytestring &restofdata &transient;
};

# For both, dh_anon and dhe the ServerKeyExchange starts with a ServerDHParams
# structure. After that, they start to differ, but we do not care about that.
type DhServerKeyExchange(rec: SSLRecord) = record {
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
type CertificateRequest(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};


######################################################################
# V3 Server Hello Done (7.4.5.)
######################################################################

# Server Hello Done is empty
type ServerHelloDone(rec: SSLRecord) = empty;


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
type ClientKeyExchange(rec: SSLRecord) = record {
	key : bytestring &restofdata &transient;
};

######################################################################
# V2 Client Master Key (SSLv2 2.5.)
######################################################################

type V2ClientMasterKey(rec: SSLRecord) = record {
	cipher_kind_8 : uint8;
	cl_key_len : uint16;
	en_key_len : uint16;
	key_arg_len : uint16;
	cl_key_data : bytestring &length = cl_key_len &transient;
	en_key_data : bytestring &length = en_key_len &transient;
	key_arg_data : bytestring &length = key_arg_len &transient;
} &length = 7 + cl_key_len + en_key_len + key_arg_len, &let {
	cipher_kind : int = (((rec.head3 << 16) | (rec.head4 << 8)) | cipher_kind_8);
	# encryption starts for both sides after this message.
	state_changed_client : bool = $context.connection.startEncryption(true);
	state_changed_server : bool = $context.connection.startEncryption(false);
};


######################################################################
# V3 Certificate Verify (7.4.8.)
######################################################################

# For now, ignore Certificate Verify; just eat up the message.
type CertificateVerify(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};


######################################################################
# V3 Finished (7.4.9.)
######################################################################

# The finished messages are always sent after encryption is in effect,
# so we will not be able to read those messages.
type Finished(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};

type SessionTicketHandshake(rec: SSLRecord) = record {
	ticket_lifetime_hint: uint32;
	data:                 bytestring &restofdata;
};

######################################################################
# V3 Handshake Protocol (7.)
######################################################################

type UnknownHandshake(hs: Handshake, is_orig: bool) = record {
	data : bytestring &restofdata &transient;
};

type Handshake(rec: SSLRecord) = record {
	msg_type : uint8;
	length : uint24;

	body : case msg_type of {
		HELLO_REQUEST       -> hello_request       : HelloRequest(rec);
		CLIENT_HELLO        -> client_hello        : ClientHello(rec);
		SERVER_HELLO        -> server_hello        : ServerHello(rec);
		SESSION_TICKET      -> session_ticket      : SessionTicketHandshake(rec);
		CERTIFICATE         -> certificate         : Certificate(rec);
		SERVER_KEY_EXCHANGE -> server_key_exchange : ServerKeyExchange(rec);
		CERTIFICATE_REQUEST -> certificate_request : CertificateRequest(rec);
		SERVER_HELLO_DONE   -> server_hello_done   : ServerHelloDone(rec);
		CERTIFICATE_VERIFY  -> certificate_verify  : CertificateVerify(rec);
		CLIENT_KEY_EXCHANGE -> client_key_exchange : ClientKeyExchange(rec);
		FINISHED            -> finished            : Finished(rec);
		CERTIFICATE_URL     -> certificate_url     : bytestring &restofdata &transient;
		CERTIFICATE_STATUS  -> certificate_status  : CertificateStatus(rec);
		default             -> unknown_handshake   : UnknownHandshake(this, rec.is_orig);
	} &length = to_int()(length);
};


######################################################################
# Fragmentation (6.2.1.)
######################################################################

type UnknownRecord(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};

type CiphertextRecord(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};


######################################################################
# initial datatype for binpac
######################################################################

type SSLPDU(is_orig: bool) = record {
	records : SSLRecord(is_orig)[] &transient;
} &byteorder = bigendian;


######################################################################
# binpac analyzer for SSL including
######################################################################

refine connection SSL_Conn += {

	%member{
		int client_state_;
		int server_state_;
		int record_layer_version_;
		uint32 chosen_cipher_;
	%}

	%init{
		server_state_ = STATE_CLEAR;
		client_state_ = STATE_CLEAR;
		record_layer_version_ = UNKNOWN_VERSION;
		chosen_cipher_ = NO_CHOSEN_CIPHER;
	%}

	function chosen_cipher() : int %{ return chosen_cipher_; %}

	function set_cipher(cipher: uint32) : bool
		%{
		chosen_cipher_ = cipher;
		return true;
		%}

	function determine_ssl_record_layer(head0 : uint8, head1 : uint8,
					head2 : uint8, head3: uint8, head4: uint8) : int
		%{
		// re-check record layer version to be sure that we still are synchronized with
		// the data stream
		if ( record_layer_version_ != UNKNOWN_VERSION && record_layer_version_ != SSLv20 )
			{
			uint16 version = (head1<<8) | head2;
			if ( version != SSLv30 && version != TLSv10 &&
			     version != TLSv11 && version != TLSv12 )
				{
				bro_analyzer()->ProtocolViolation(fmt("Invalid version late in TLS connection. Packet reported version: %d", version));
				return UNKNOWN_VERSION;
				}
			}

		if ( record_layer_version_ != UNKNOWN_VERSION )
			return record_layer_version_;

		if ( head0 & 0x80 )
			{
			if ( head2 == 0x01 ) // SSLv2 client hello.
				{
				uint16 version = (head3 << 8) | head4;
				if ( version != SSLv20 && version != SSLv30 && version != TLSv10 &&
				     version != TLSv11 && version != TLSv12 )
					{
					bro_analyzer()->ProtocolViolation(fmt("Invalid version in SSL client hello. Version: %d", version));
					return UNKNOWN_VERSION;
					}

				else
					return SSLv20;
				}

			else if ( head2 == 0x04 ) // SSLv2 server hello. This connection will continue using SSLv2.
				{
				record_layer_version_ = SSLv20;
				return SSLv20;
				}

			else // this is not SSL or TLS.
				{
				bro_analyzer()->ProtocolViolation(fmt("Invalid headers in SSL connection. Head1: %d, head2: %d, head3: %d", head1, head2, head3));
				return UNKNOWN_VERSION;
				}
			}

		uint16 version = (head1<<8) | head2;
		if ( version != SSLv30 && version != TLSv10 &&
		     version != TLSv11 && version != TLSv12 )
			{
			bro_analyzer()->ProtocolViolation(fmt("Invalid version in TLS connection. Version: %d", version));
			return UNKNOWN_VERSION;
			}

		if ( head0 >=20 && head0 <= 30 )
			{ // ok, set record layer version, this never can be downgraded to v2
			record_layer_version_ = version;
			return version;
			}

		bro_analyzer()->ProtocolViolation(fmt("Invalid type in TLS connection. Version: %d, Type: %d", version, head0));
		return UNKNOWN_VERSION;
		%}

	function client_state() : int %{ return client_state_; %}

	function server_state() : int %{ return client_state_; %}

	function state(is_orig: bool) : int
		%{
		if ( is_orig )
			return client_state_;
		else
			return server_state_;
		%}

	function startEncryption(is_orig: bool) : bool
		%{
		if ( is_orig )
			client_state_ = STATE_ENCRYPTED;
		else
			server_state_ = STATE_ENCRYPTED;
		return true;
		%}
};
