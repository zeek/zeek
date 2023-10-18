
######################################################################
# General definitions
######################################################################

type PlaintextRecord(rec: SSLRecord) = case rec.content_type of {
	CHANGE_CIPHER_SPEC	-> ch_cipher : ChangeCipherSpec(rec);
	ALERT			-> alerts : Alerts(rec);
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
			return string(zeek::util::fmt("UNKNOWN (%d)", state_nr));
		}
		}
%}

######################################################################
# Change Cipher Spec Protocol (7.1.)
######################################################################

type ChangeCipherSpec(rec: SSLRecord) = record {
	type : uint8;
} &length = 1, &let {
	# I know this looks a bit weird. Basically - in TLS 1.3, CCS is meaningless
	# fluff that just is used to pretend to TLS 1.2 devices listening in that
	# yes, this is TLS. Since we want to know which packets come after this,
	# and since we do have special handling for TLS 1.3 - let's ignore it in
	# that case.
	state_changed : bool = case $context.connection.determine_tls13() of {
		1 -> false;
		0 -> $context.connection.startEncryption(rec.is_orig);
	};
};


######################################################################
# Alert Protocol (7.2.)
######################################################################

type Alerts(rec: SSLRecord) = record {
	alerts: Alert(rec)[] &length=$context.connection.cap_alert_messages_length(rec.length);
	rest: bytestring &restofdata &transient;
} &length=rec.length;

type Alert(rec: SSLRecord) = record {
	level : uint8;
	description: uint8;
};


######################################################################
# V3 Application Data
######################################################################

# Application data should always be encrypted, so we should not
# reach this point, unless we are in TLS 1.3 ...
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
# Unknown Records (6.2.1.)
######################################################################

# We should never reach this.
type UnknownRecord(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};

type CiphertextRecord(rec: SSLRecord) = record {
	cont : bytestring &restofdata &transient;
};

######################################################################
# binpac analyzer for SSL including
######################################################################

%extern{
#include "zeek/analyzer/protocol/ssl/consts.bif.h"
%}

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

	function determine_tls13() : int
		%{
		// let's be conservative and only return yes if it has a valid TLS 1.3 version number here.
		uint16_t negotiated_version = zeek_analyzer()->GetNegotiatedVersion();
		if ( negotiated_version == TLSv13 || negotiated_version/0xFF == 0x7F )
			return 1;

		return 0;
		%}

	function cap_alert_messages_length(record_length: int) : int
		%{
		int alert_length = record_length;
		int max_length = zeek::BifConst::SSL::max_alerts_per_record * 2;

		// With TLS 1.3, enforce a single alert.
		//
		// From https://datatracker.ietf.org/doc/html/rfc8446//section-5.1
		//
		//    Alert messages (Section 6) MUST NOT be fragmented across records, and
		//    multiple alert messages MUST NOT be coalesced into a single
		//    record.  In other words, a record with an Alert type MUST contain
		//    exactly one message.
		if ( determine_tls13() )
			max_length = 2;

		if ( alert_length > max_length )
			{
			zeek_analyzer()->Weird("SSL_excessive_alerts_in_record", zeek::util::fmt("%d", alert_length / 2));
			alert_length = max_length;
			}

		return alert_length;
		%}
};
