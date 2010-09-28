# $Id:$

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
%}

extern type to_int;

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

	string orig_label(bool is_orig)
		{
		return string(is_orig ? "originator" :"responder");
		}
%}

######################################################################
# SSLv3 Handshake Protocols (7.)
######################################################################

enum HandshakeType {
	HELLO_REQUEST		= 0,
	CLIENT_HELLO		= 1,
	SERVER_HELLO		= 2,
	CERTIFICATE		= 11,
	SERVER_KEY_EXCHANGE	= 12,
	CERTIFICATE_REQUEST	= 13,
	SERVER_HELLO_DONE	= 14,
	CERTIFICATE_VERIFY	= 15,
	CLIENT_KEY_EXCHANGE	= 16,
	FINISHED		= 20
};

%code{
	string handshake_type_label(int type)
		{
		switch ( type ) {
		case HELLO_REQUEST: return string("HELLO_REQUEST");
		case CLIENT_HELLO: return string("CLIENT_HELLO");
		case SERVER_HELLO: return string("SERVER_HELLO");
		case CERTIFICATE: return string("CERTIFICATE");
		case SERVER_KEY_EXCHANGE: return string("SERVER_KEY_EXCHANGE");
		case CERTIFICATE_REQUEST: return string("CERTIFICATE_REQUEST");
		case SERVER_HELLO_DONE: return string("SERVER_HELLO_DONE");
		case CERTIFICATE_VERIFY: return string("CERTIFICATE_VERIFY");
		case CLIENT_KEY_EXCHANGE: return string("CLIENT_KEY_EXCHANGE");
		case FINISHED: return string("FINISHED");
		default: return string(fmt("UNKNOWN (%d)", type));
		}
		}
%}


######################################################################
# V3 Change Cipher Spec Protocol (7.1.)
######################################################################

type ChangeCipherSpec = record {
	type : uint8;
} &length = 1, &let {
	state_changed : bool =
	    $context.analyzer.transition(STATE_CLIENT_FINISHED,
					 STATE_COMM_ENCRYPTED, false) ||
	    $context.analyzer.transition(STATE_IN_SERVER_HELLO,
					 STATE_ABBREV_SERVER_ENCRYPTED, false) ||
	    $context.analyzer.transition(STATE_CLIENT_KEY_NO_CERT,
					 STATE_CLIENT_ENCRYPTED, true) ||
	    $context.analyzer.transition(STATE_CLIENT_CERT_VERIFIED,
					 STATE_CLIENT_ENCRYPTED, true) ||
	    $context.analyzer.transition(STATE_CLIENT_KEY_WITH_CERT,
					 STATE_CLIENT_ENCRYPTED, true) ||
	    $context.analyzer.transition(STATE_ABBREV_SERVER_FINISHED,
					 STATE_COMM_ENCRYPTED, true) ||
	    $context.analyzer.lost_track();
};


######################################################################
# V3 Alert Protocol (7.2.)
######################################################################

type Alert = record {
	level : uint8;
	description: uint8;
} &length = 2;


######################################################################
# V2 Error Records (SSLv2 2.7.)
######################################################################

type V2Error = record {
	error_code : uint16;
} &length = 2;


######################################################################
# V3 Application Data
######################################################################

# Application data should always be encrypted, so we should not
# reach this point.
type ApplicationData = empty &let {
	discard: bool = $context.flow.discard_data();
};

######################################################################
# Handshake Protocol (7.4.)
######################################################################

######################################################################
# V3 Hello Request (7.4.1.1.)
######################################################################

# Hello Request is empty
type HelloRequest = empty &let {
	hr: bool = $context.analyzer.set_hello_requested(true);
};


######################################################################
# V3 Client Hello (7.4.1.2.)
######################################################################

type ClientHello = record {
	client_version : uint16;
	gmt_unix_time : uint32;
	random_bytes : bytestring &length = 28 &transient;
	session_len : uint8;
	session_id : uint8[session_len];
	csuit_len : uint16 &check(csuit_len > 1 && csuit_len % 2 == 0);
	csuits : uint16[csuit_len/2];
	cmeth_len : uint8 &check(cmeth_len > 0);
	cmeths : uint8[cmeth_len];
} &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_INITIAL,
				STATE_CLIENT_HELLO_RCVD, true) ||
		($context.analyzer.hello_requested() &&
		 $context.analyzer.transition(STATE_ANY, STATE_CLIENT_HELLO_RCVD, true)) ||
		$context.analyzer.lost_track();
};


######################################################################
# V2 Client Hello (SSLv2 2.5.)
######################################################################

type V2ClientHello = record {
	client_version : uint16;
	csuit_len : uint16;
	session_len : uint16;
	chal_len : uint16;
	ciphers : uint24[csuit_len/3];
	session_id : uint8[session_len];
	challenge : bytestring &length = chal_len;
} &length = 8 + csuit_len + session_len + chal_len, &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_INITIAL,
			STATE_CLIENT_HELLO_RCVD, true) ||
		($context.analyzer.hello_requested() &&
		 $context.analyzer.transition(STATE_ANY, STATE_CLIENT_HELLO_RCVD, true)) ||
		$context.analyzer.lost_track();
};


######################################################################
# V3 Server Hello (7.4.1.3.)
######################################################################

type ServerHello = record {
	server_version : uint16;
	gmt_unix_time : uint32;
	random_bytes : bytestring &length = 28 &transient;
	session_len : uint8;
	session_id : uint8[session_len];
	cipher_suite : uint16[1];
	compression_method : uint8;
} &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_CLIENT_HELLO_RCVD,
					   STATE_IN_SERVER_HELLO, false) ||
		$context.analyzer.lost_track();
};


######################################################################
# V2 Server Hello (SSLv2 2.6.)
######################################################################

type V2ServerHello = record {
	session_id_hit : uint8;
	cert_type : uint8;
	server_version : uint16;
	cert_len : uint16;
	ciph_len : uint16;
	conn_id_len : uint16;
	cert_data : bytestring &length = cert_len;
	ciphers : uint24[ciph_len/3];
	conn_id_data : bytestring &length = conn_id_len;
} &length = 10 + cert_len + ciph_len + conn_id_len, &let {
	state_changed : bool =
		(session_id_hit > 0 ?
			$context.analyzer.transition(STATE_CLIENT_HELLO_RCVD,
				STATE_CONN_ESTABLISHED, false) :
			$context.analyzer.transition(STATE_CLIENT_HELLO_RCVD,
				STATE_V2_CL_MASTER_KEY_EXPECTED, false)) ||
		$context.analyzer.lost_track();
};


######################################################################
# V3 Server Certificate (7.4.2.)
######################################################################

type X509Certificate = record {
	length : uint24;
	certificate : bytestring &length = to_int()(length);
};

type CertificateList = X509Certificate[] &until($input.length() == 0);

type Certificate = record {
	length : uint24;
	certificates : CertificateList &length = to_int()(length);
} &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_IN_SERVER_HELLO,
					STATE_IN_SERVER_HELLO, false) ||
		$context.analyzer.transition(STATE_SERVER_HELLO_DONE,
					STATE_CLIENT_CERT, true) ||
		$context.analyzer.lost_track();
};


######################################################################
# V3 Server Key Exchange Message (7.4.3.)
######################################################################

# For now ignore details; just eat up complete message
type ServerKeyExchange = record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_IN_SERVER_HELLO,
				STATE_IN_SERVER_HELLO, false) ||
		$context.analyzer.lost_track();
};


######################################################################
# V3 Certificate Request (7.4.4.)
######################################################################

# For now, ignore Certificate Request Details; just eat up message.
type CertificateRequest = record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_IN_SERVER_HELLO,
					STATE_IN_SERVER_HELLO, false) ||
		$context.analyzer.lost_track();
};


######################################################################
# V3 Server Hello Done (7.4.5.)
######################################################################

# Server Hello Done is empty
type ServerHelloDone = empty &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_IN_SERVER_HELLO,
					STATE_SERVER_HELLO_DONE, false) ||
		$context.analyzer.lost_track();
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
type ClientKeyExchange = record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_SERVER_HELLO_DONE,
					STATE_CLIENT_KEY_NO_CERT, true) ||
		$context.analyzer.transition(STATE_CLIENT_CERT,
					STATE_CLIENT_KEY_WITH_CERT, true) ||
		$context.analyzer.lost_track();
};

######################################################################
# V2 Client Master Key (SSLv2 2.5.)
######################################################################

type V2ClientMasterKey = record {
	cipher_kind : uint24;
	cl_key_len : uint16;
	en_key_len : uint16;
	key_arg_len : uint16;
	cl_key_data : bytestring &length = cl_key_len &transient;
	en_key_data : bytestring &length = en_key_len &transient;
	key_arg_data : bytestring &length = key_arg_len &transient;
} &length = 9 + cl_key_len + en_key_len + key_arg_len, &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_V2_CL_MASTER_KEY_EXPECTED,
					STATE_CONN_ESTABLISHED, true) ||
		$context.analyzer.lost_track();
};


######################################################################
# V3 Certificate Verify (7.4.8.)
######################################################################

# For now, ignore Certificate Verify; just eat up the message.
type CertificateVerify = record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool =
		$context.analyzer.transition(STATE_CLIENT_KEY_WITH_CERT,
					STATE_CLIENT_CERT_VERIFIED, true) ||
		$context.analyzer.lost_track();
};


######################################################################
# V3 Finished (7.4.9.)
######################################################################

# The Finished messages are always sent after encryption is in effect,
# so we will not be able to read those message


######################################################################
# V3 Handshake Protocol (7.)
######################################################################

type UnknownHandshake(msg_type : uint8) =  record {
	cont : bytestring &restofdata &transient;
} &let {
	state_changed : bool = $context.analyzer.lost_track();
};

type Handshake = record {
	msg_type : uint8;
	length : uint24;

	body : case msg_type of {
	HELLO_REQUEST ->	hello_request : HelloRequest;
	CLIENT_HELLO ->		client_hello : ClientHello;
	SERVER_HELLO ->		server_hello : ServerHello;
	CERTIFICATE ->		certificate : Certificate;
	SERVER_KEY_EXCHANGE ->	server_key_exchange : ServerKeyExchange;
	CERTIFICATE_REQUEST ->	certificate_request : CertificateRequest;
	SERVER_HELLO_DONE ->	server_hello_done : ServerHelloDone;
	CERTIFICATE_VERIFY ->	certificate_verify : CertificateVerify;
	CLIENT_KEY_EXCHANGE ->	client_key_exchange : ClientKeyExchange;
	default ->		unknown_handshake : UnknownHandshake(msg_type);
	};
} &length = 4 + to_int()(length);


######################################################################
# Fragmentation (6.2.1.)
######################################################################

type UnknownRecord =  record {
	cont : empty;
} &let {
	discard : bool = $context.flow.discard_data();
	state_changed : bool = $context.analyzer.lost_track();
};

type PlaintextRecord =  case $context.analyzer.current_record_type() of {
	CHANGE_CIPHER_SPEC	-> ch_cipher : ChangeCipherSpec;
	ALERT			-> alert : Alert;
	HANDSHAKE		-> handshakes : Handshake;
	APPLICATION_DATA	-> app_data : ApplicationData;
	V2_ERROR		-> v2_error : V2Error;
	V2_CLIENT_HELLO		-> v2_client_hello : V2ClientHello;
	V2_CLIENT_MASTER_KEY	-> v2_client_master_key : V2ClientMasterKey;
	V2_SERVER_HELLO		-> v2_server_hello : V2ServerHello;
	UNKNOWN_OR_V2_ENCRYPTED	-> unknown_record : UnknownRecord;
};

type CiphertextRecord = empty &let {
	discard : bool = $context.flow.discard_data();
	state_changed : bool =
		$context.analyzer.transition(STATE_ABBREV_SERVER_ENCRYPTED,
					STATE_ABBREV_SERVER_FINISHED, false) ||
		$context.analyzer.transition(STATE_CLIENT_ENCRYPTED,
					STATE_CLIENT_FINISHED, true) ||
		$context.analyzer.transition(STATE_COMM_ENCRYPTED,
					STATE_CONN_ESTABLISHED, false) ||
		$context.analyzer.transition(STATE_COMM_ENCRYPTED,
					STATE_CONN_ESTABLISHED, true) ||
		$context.analyzer.transition(STATE_CONN_ESTABLISHED,
					STATE_CONN_ESTABLISHED, false) ||
		$context.analyzer.transition(STATE_CONN_ESTABLISHED,
					STATE_CONN_ESTABLISHED, true) ||
		$context.analyzer.lost_track();
};


######################################################################
# initial datatype for binpac
######################################################################

type SSLPDU = case $context.analyzer.state() of {
	STATE_ABBREV_SERVER_ENCRYPTED, STATE_CLIENT_ENCRYPTED,
	STATE_COMM_ENCRYPTED, STATE_CONN_ESTABLISHED
		-> ciphertext : CiphertextRecord;
	default
		-> plaintext : PlaintextRecord;
} &byteorder = bigendian, &let {
	consumed : bool = $context.flow.consume_data();
};


######################################################################
# binpac analyzer for SSL including
######################################################################

analyzer SSLAnalyzer {
	upflow = SSLFlow(true);
	downflow = SSLFlow(false);

	%member{
		int current_record_type_;
		int current_record_version_;
		int current_record_length_;
		bool current_record_is_orig_;
		int state_;
		int old_state_;
		bool hello_requested_;
	%}

	%init{
		current_record_type_ = -1;
		current_record_version_ = -1;
		current_record_length_ = -1;
		current_record_is_orig_ = false;
		state_ = STATE_INITIAL;
		old_state_ = STATE_INITIAL;
		hello_requested_ = false;
	%}

	function current_record_type() : int
					%{ return current_record_type_; %}
	function current_record_version() : int
					%{ return current_record_version_; %}
	function current_record_length() : int
					%{ return current_record_length_; %}
	function current_record_is_orig() : bool
					%{ return current_record_is_orig_; %}

	function next_record(rec : const_bytestring, type : int,
				version : int, is_orig : bool) : bool
		%{
		current_record_type_ = type;
		current_record_version_ = version;
		current_record_length_ = rec.length();
		current_record_is_orig_ = is_orig;

		NewData(is_orig, rec.begin(), rec.end());

		return true;
		%}

	function state() : int %{ return state_; %}
	function old_state() : int %{ return old_state_; %}

	function transition(olds : AnalyzerState, news : AnalyzerState,
				is_orig : bool) : bool
		%{
		if ( (olds != STATE_ANY && olds != state_) ||
		     current_record_is_orig_ != is_orig )
			return false;

		old_state_ = state_;
		state_ = news;

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


######################################################################
# binpac flow for SSL
######################################################################

flow SSLFlow(is_orig : bool) {
	flowunit = SSLPDU withcontext(connection, this);

	function discard_data() : bool
		%{
		flow_buffer_->DiscardData();
		return true;
		%}

	function data_available() : bool
		%{
		return flow_buffer_->data_available();
		%}

	function consume_data() : bool
		%{
		flow_buffer_->NewFrame(0, false);
		return true;
		%}
};
