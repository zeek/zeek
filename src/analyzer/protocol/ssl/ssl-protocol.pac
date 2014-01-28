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
		$context.connection.determine_ssl_version(head0, head1, head2);

	content_type : int = case version of {
		UNKNOWN_VERSION -> 0;
		SSLv20 -> head2+300;
		default -> head0;
	};

	length : int = case version of {
		UNKNOWN_VERSION -> 0;
		SSLv20 -> (((head0 & 0x7f) << 8) | head1) - 3;
		default -> (head3 << 8) | head4;
	};
};

type RecordText(rec: SSLRecord) = case $context.connection.state() of {
	STATE_ABBREV_SERVER_ENCRYPTED, STATE_CLIENT_ENCRYPTED,
	STATE_COMM_ENCRYPTED, STATE_CONN_ESTABLISHED
		-> ciphertext : CiphertextRecord(rec);
	default
		-> plaintext : PlaintextRecord(rec);
};

type PlaintextRecord(rec: SSLRecord) = case rec.content_type of {
	CHANGE_CIPHER_SPEC	-> ch_cipher : ChangeCipherSpec(rec);
	ALERT			-> alert : Alert(rec);
	HANDSHAKE		-> handshake : Handshake(rec);
	APPLICATION_DATA	-> app_data : ApplicationData(rec);
	V2_ERROR		-> v2_error : V2Error(rec);
	V2_CLIENT_HELLO		-> v2_client_hello : V2ClientHello(rec);
	V2_CLIENT_MASTER_KEY	-> v2_client_master_key : V2ClientMasterKey(rec);
	V2_SERVER_HELLO		-> v2_server_hello : V2ServerHello(rec);
	default			-> unknown_record : UnknownRecord(rec);
};

type SSLExtension(rec: SSLRecord) = record {
	type: uint16;
	data_len: uint16;
	data: bytestring &length=data_len;
};

######################################################################
# state management according to Section 7.3. in spec
######################################################################

enum AnalyzerState {
	STATE_INITIAL,
	STATE_CLIENT_HELLO_RCVD,
	STATE_IN_SERVER_HELLO,
	STATE_SERVER_HELLO_DONE,
	STATE_CLIENT_CERT,
	STATE_CLIENT_KEY_WITH_CERT,
	STATE_CLIENT_KEY_NO_CERT,
	STATE_CLIENT_CERT_VERIFIED,
	STATE_CLIENT_ENCRYPTED,
	STATE_CLIENT_FINISHED,
	STATE_ABBREV_SERVER_ENCRYPTED,
	STATE_ABBREV_SERVER_FINISHED,
	STATE_COMM_ENCRYPTED,
	STATE_CONN_ESTABLISHED,
	STATE_V2_CL_MASTER_KEY_EXPECTED,

	STATE_TRACK_LOST,
	STATE_ANY
};

%code{
	string state_label(int state_nr)
		{
		switch ( state_nr ) {
		case STATE_INITIAL:
			return string("INITIAL");
		case STATE_CLIENT_HELLO_RCVD:
			return string("CLIENT_HELLO_RCVD");
		case STATE_IN_SERVER_HELLO:
			return string("IN_SERVER_HELLO");
		case STATE_SERVER_HELLO_DONE:
			return string("SERVER_HELLO_DONE");
		case STATE_CLIENT_CERT:
			return string("CLIENT_CERT");
		case STATE_CLIENT_KEY_WITH_CERT:
			return string("CLIENT_KEY_WITH_CERT");
		case STATE_CLIENT_KEY_NO_CERT:
			return string("CLIENT_KEY_NO_CERT");
		case STATE_CLIENT_CERT_VERIFIED:
			return string("CLIENT_CERT_VERIFIED");
		case STATE_CLIENT_ENCRYPTED:
			return string("CLIENT_ENCRYPTED");
		case STATE_CLIENT_FINISHED:
			return string("CLIENT_FINISHED");
		case STATE_ABBREV_SERVER_ENCRYPTED:
			return string("ABBREV_SERVER_ENCRYPTED");
		case STATE_ABBREV_SERVER_FINISHED:
			return string("ABBREV_SERVER_FINISHED");
		case STATE_COMM_ENCRYPTED:
			return string("COMM_ENCRYPTED");
		case STATE_CONN_ESTABLISHED:
			return string("CONN_ESTABLISHED");
		case STATE_V2_CL_MASTER_KEY_EXPECTED:
			return string("STATE_V2_CL_MASTER_KEY_EXPECTED");
		case STATE_TRACK_LOST:
			return string("TRACK_LOST");
		case STATE_ANY:
			return string("ANY");

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
		$context.connection.transition(STATE_CLIENT_FINISHED,
					 STATE_COMM_ENCRYPTED, rec.is_orig, false) ||
		$context.connection.transition(STATE_IN_SERVER_HELLO,
					 STATE_ABBREV_SERVER_ENCRYPTED, rec.is_orig, false) ||
		$context.connection.transition(STATE_CLIENT_KEY_NO_CERT,
					 STATE_CLIENT_ENCRYPTED, rec.is_orig, true) ||
		$context.connection.transition(STATE_CLIENT_CERT_VERIFIED,
					 STATE_CLIENT_ENCRYPTED, rec.is_orig, true) ||
		$context.connection.transition(STATE_CLIENT_CERT,
					 STATE_CLIENT_ENCRYPTED, rec.is_orig, true) ||
		$context.connection.transition(STATE_CLIENT_KEY_WITH_CERT,
					 STATE_CLIENT_ENCRYPTED, rec.is_orig, true) ||
		$context.connection.transition(STATE_ABBREV_SERVER_FINISHED,
					 STATE_COMM_ENCRYPTED, rec.is_orig, true) ||
		$context.connection.lost_track();
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
	data:   bytestring &restofdata &transient;
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
# Handshake Protocol (7.4.)
######################################################################

######################################################################
# V3 Hello Request (7.4.1.1.)
######################################################################

# Hello Request is empty
type HelloRequest(rec: SSLRecord) = empty &let {
	hr: bool = $context.connection.set_hello_requested(true);
};


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
} &let {
	state_changed : bool =
		$context.connection.transition(STATE_INITIAL,
				STATE_CLIENT_HELLO_RCVD, rec.is_orig, true) ||
		($context.connection.hello_requested() &&
		 $context.connection.transition(STATE_ANY, STATE_CLIENT_HELLO_RCVD, rec.is_orig, true)) ||
		$context.connection.lost_track();
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
	state_changed : bool =
		$context.connection.transition(STATE_INITIAL,
			STATE_CLIENT_HELLO_RCVD, rec.is_orig, true) ||
		($context.connection.hello_requested() &&
		 $context.connection.transition(STATE_ANY, STATE_CLIENT_HELLO_RCVD, rec.is_orig, true)) ||
		$context.connection.lost_track();

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
	state_changed : bool =
		$context.connection.transition(STATE_CLIENT_HELLO_RCVD,
					   STATE_IN_SERVER_HELLO, rec.is_orig, false) ||
		$context.connection.lost_track();
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
	state_changed : bool =
		(session_id_hit > 0 ?
			$context.connection.transition(STATE_CLIENT_HELLO_RCVD,
				STATE_CONN_ESTABLISHED, rec.is_orig, false) :
			$context.connection.transition(STATE_CLIENT_HELLO_RCVD,
				STATE_V2_CL_MASTER_KEY_EXPECTED, rec.is_orig, false)) ||
		$context.connection.lost_track();

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

type CertificateList = X509Certificate[] &until($input.length() == 0);

type Certificate(rec: SSLRecord) = record {
	length : uint24;
	certificates : CertificateList &length = to_int()(length);
} &let {
	state_changed : bool =
		$context.connection.transition(STATE_IN_SERVER_HELLO,
					STATE_IN_SERVER_HELLO, rec.is_orig, false) ||
		$context.connection.transition(STATE_SERVER_HELLO_DONE,
					STATE_CLIENT_CERT, rec.is_orig, true) ||
		$context.connection.lost_track();
};


######################################################################
# V3 Server Key Exchange Message (7.4.3.)
######################################################################

# For now ignore details; just eat up complete message
type ServerKeyExchange(rec: SSLRecord) = record {
	key : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.connection.transition(STATE_IN_SERVER_HELLO,
				STATE_IN_SERVER_HELLO, rec.is_orig, false) ||
		$context.connection.lost_track();
};


######################################################################
# V3 Certificate Request (7.4.4.)
######################################################################

# For now, ignore Certificate Request Details; just eat up message.
type CertificateRequest(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.connection.transition(STATE_IN_SERVER_HELLO,
					STATE_IN_SERVER_HELLO, rec.is_orig, false) ||
		$context.connection.lost_track();
};


######################################################################
# V3 Server Hello Done (7.4.5.)
######################################################################

# Server Hello Done is empty
type ServerHelloDone(rec: SSLRecord) = empty &let {
	state_changed : bool =
		$context.connection.transition(STATE_IN_SERVER_HELLO,
					STATE_SERVER_HELLO_DONE, rec.is_orig, false) ||
		$context.connection.lost_track();
};


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
} &let {
	state_changed : bool =
		$context.connection.transition(STATE_SERVER_HELLO_DONE,
					STATE_CLIENT_KEY_NO_CERT, rec.is_orig, true) ||
		$context.connection.transition(STATE_CLIENT_CERT,
					STATE_CLIENT_KEY_WITH_CERT, rec.is_orig, true) ||
		$context.connection.transition(STATE_CLIENT_CERT,
					STATE_CLIENT_KEY_WITH_CERT, rec.is_orig, true) ||
		$context.connection.lost_track();
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
	state_changed : bool =
		$context.connection.transition(STATE_V2_CL_MASTER_KEY_EXPECTED,
					STATE_CONN_ESTABLISHED, rec.is_orig, true) ||
		$context.connection.lost_track();

	cipher_kind : int = (((rec.head3 << 16) | (rec.head4 << 8)) | cipher_kind_8);
};


######################################################################
# V3 Certificate Verify (7.4.8.)
######################################################################

# For now, ignore Certificate Verify; just eat up the message.
type CertificateVerify(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.connection.transition(STATE_CLIENT_KEY_WITH_CERT,
					STATE_CLIENT_CERT_VERIFIED, rec.is_orig, true) ||
		$context.connection.lost_track();
};


######################################################################
# V3 Finished (7.4.9.)
######################################################################

# The finished messages are always sent after encryption is in effect,
# so we will not be able to read those messages.
type Finished(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.connection.transition(STATE_SERVER_HELLO_DONE,
					STATE_COMM_ENCRYPTED, rec.is_orig, true) ||
		$context.connection.transition(STATE_CLIENT_FINISHED,
					STATE_COMM_ENCRYPTED, rec.is_orig, false) ||
		$context.connection.lost_track();
};

type SessionTicketHandshake(rec: SSLRecord) = record {
	ticket_lifetime_hint: uint32;
	data:                 bytestring &restofdata;
};

######################################################################
# V3 Handshake Protocol (7.)
######################################################################

type UnknownHandshake(hs: Handshake, is_orig: bool) =  record {
	data : bytestring &restofdata &transient;
} &let {
	state_changed : bool = $context.connection.lost_track();
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
		CERTIFICATE_STATUS  -> certificate_status  : bytestring &restofdata &transient;
		default             -> unknown_handshake   : UnknownHandshake(this, rec.is_orig);
	} &length = to_int()(length);
};


######################################################################
# Fragmentation (6.2.1.)
######################################################################

type UnknownRecord(rec: SSLRecord) =  record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool = $context.connection.lost_track();
};

type CiphertextRecord(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.connection.transition(STATE_CLIENT_FINISHED,
					STATE_CLIENT_FINISHED, rec.is_orig, false) ||
		$context.connection.transition(STATE_CLIENT_FINISHED,
					STATE_CLIENT_FINISHED, rec.is_orig, true) ||
		$context.connection.transition(STATE_ABBREV_SERVER_ENCRYPTED,
					STATE_ABBREV_SERVER_FINISHED, rec.is_orig, false) ||
		$context.connection.transition(STATE_CLIENT_ENCRYPTED,
					STATE_CLIENT_FINISHED, rec.is_orig, true) ||
		$context.connection.transition(STATE_COMM_ENCRYPTED,
					STATE_CONN_ESTABLISHED, rec.is_orig, false) ||
		$context.connection.transition(STATE_COMM_ENCRYPTED,
					STATE_CONN_ESTABLISHED, rec.is_orig, true) ||
		$context.connection.transition(STATE_CONN_ESTABLISHED,
					STATE_CONN_ESTABLISHED, rec.is_orig, false) ||
		$context.connection.transition(STATE_CONN_ESTABLISHED,
					STATE_CONN_ESTABLISHED, rec.is_orig, true) ||
		$context.connection.lost_track();
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
		int state_;
		int old_state_;
		bool hello_requested_;
	%}

	%init{
		state_ = STATE_INITIAL;
		old_state_ = STATE_INITIAL;
		hello_requested_ = false;
	%}

	function determine_ssl_version(head0 : uint8, head1 : uint8,
					head2 : uint8) : int
		%{
		if ( head0 >= 20 && head0 <= 23 &&
		     head1 == 0x03 && head2 <= 0x03 )
			// This is most probably SSL version 3.
			return (head1 << 8) | head2;

		else if ( head0 >= 128 && head2 < 5 && head2 != 3 )
			// Not very strong evidence, but we suspect
			// this to be SSLv2.
			return SSLv20;

		else
			return UNKNOWN_VERSION;
		%}

	function state() : int %{ return state_; %}
	function old_state() : int %{ return old_state_; %}

	function transition(olds : AnalyzerState, news : AnalyzerState,
				current_record_is_orig : bool, is_orig : bool) : bool
		%{
		if ( (olds != STATE_ANY && olds != state_) ||
		     current_record_is_orig != is_orig )
			return false;

		old_state_ = state_;
		state_ = news;

		//printf("transitioning from %s to %s\n", state_label(old_state()).c_str(), state_label(state()).c_str());
		return true;
		%}

	function lost_track() : bool
		%{
		state_ = STATE_TRACK_LOST;
		return false;
		%}

	function hello_requested() : bool
		%{
		bool ret = hello_requested_;
		hello_requested_ = false;
		return ret;
		%}

	function set_hello_requested(val : bool) : bool
		%{
		hello_requested_ = val;
		return val;
		%}
};
