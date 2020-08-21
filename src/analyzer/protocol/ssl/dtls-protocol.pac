
######################################################################
# initial datatype for binpac
######################################################################

type DTLSPDU(is_orig: bool) = record {
	records: SSLRecord(is_orig)[] &transient;
};

type SSLRecord(is_orig: bool) = record {
	content_type: uint8;
	version: uint16;
# the epoch signalizes that a changecipherspec message has been received. Hence, everything with
# an epoch > 0 should be encrypted
	epoch: uint16;
	sequence_number: uint48;
	length: uint16;
	cont: case valid of {
		true -> rec: RecordText(this)[] &length=length;
    false -> swallow: bytestring &restofdata;
	} &requires(valid,raw_tls_version);
} &byteorder = bigendian, &let {
# Do not parse body if packet version invalid
	valid: bool = $context.connection.dtls_version_ok(version);
	raw_tls_version: uint16 = version;
};

type RecordText(rec: SSLRecord) = case rec.epoch of {
	0	-> plaintext : PlaintextRecord(rec);
	default -> ciphertext : CiphertextRecord(rec);
};

refine casetype PlaintextRecord += {
	HANDSHAKE		-> handshake : Handshake(rec);
};

type Handshake(rec: SSLRecord) = record {
	msg_type: uint8;
	length: uint24;
	message_seq: uint16;
	fragment_offset: uint24;
	fragment_length: uint24;
	data: bytestring &restofdata;
}

refine connection SSL_Conn += {

	%member{
		uint16 invalid_version_count_;
		uint16 reported_errors_;
	%}

	%init{
		invalid_version_count_ = 0;
		reported_errors_ = 0;
	%}

	function dtls_version_ok(version: uint16): uint16
		%{
		switch ( version ) {
		case DTLSv10:
		case DTLSv12:
			// Reset only to 0 once we have seen a client hello.
			// This means the connection gets a limited amount of valid/invalid
			// packets before a client hello has to be seen - which seems reasonable.
			if ( bro_analyzer()->ProtocolConfirmed() )
				invalid_version_count_ = 0;
			return true;

		default:
			invalid_version_count_++;

			if ( bro_analyzer()->ProtocolConfirmed() )
				{
				reported_errors_++;
				if ( reported_errors_ <= zeek::BifConst::SSL::dtls_max_reported_version_errors )
					bro_analyzer()->ProtocolViolation(zeek::util::fmt("Invalid version in DTLS connection. Packet reported version: %d", version));
				}

			if ( invalid_version_count_ > zeek::BifConst::SSL::dtls_max_version_errors )
				bro_analyzer()->SetSkip(true);
			return false;
		}
		%}

};
