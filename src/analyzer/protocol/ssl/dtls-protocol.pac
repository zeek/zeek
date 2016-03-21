
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
	};
} &byteorder = bigendian, &let {
# Do not parse body if packet version invalid
	valid: bool = $context.connection.dtls_version_ok(version);
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

	function dtls_version_ok(version: uint16): uint16
		%{
		switch ( version ) {
		case DTLSv10:
		case DTLSv12:
			return true;

		default:
			bro_analyzer()->ProtocolViolation(fmt("Invalid version in DTLS connection. Packet reported version: %d", version));			
			return false;
		}
		%}

};
