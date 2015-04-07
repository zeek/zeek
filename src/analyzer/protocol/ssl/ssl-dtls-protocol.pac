
######################################################################
# General definitions
######################################################################

type PlaintextRecord(rec: SSLRecord) = case rec.content_type of {
	CHANGE_CIPHER_SPEC	-> ch_cipher : ChangeCipherSpec(rec);
	ALERT			-> alert : Alert(rec);
	HEARTBEAT -> heartbeat: Heartbeat(rec);
	APPLICATION_DATA	-> app_data : ApplicationData(rec);
	default			-> unknown_record : UnknownRecord(rec);
};


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
# Change Cipher Spec Protocol (7.1.)
######################################################################

type ChangeCipherSpec(rec: SSLRecord) = record {
	type : uint8;
} &length = 1, &let {
	state_changed : bool =
		$context.connection.startEncryption(rec.is_orig);
};


######################################################################
# Alert Protocol (7.2.)
######################################################################

type Alert(rec: SSLRecord) = record {
	level : uint8;
	description: uint8;
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
# Fragmentation (6.2.1.)
######################################################################

type UnknownRecord(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};

type CiphertextRecord(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};

######################################################################
# binpac analyzer for SSL including
######################################################################

refine connection SSL_Conn += {

	%member{
		int client_state_;
		int server_state_;
		int record_layer_version_;
	%}

	%init{
		server_state_ = STATE_CLEAR;
		client_state_ = STATE_CLEAR;
		record_layer_version_ = UNKNOWN_VERSION;
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
