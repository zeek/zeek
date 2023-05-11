
######################################################################
# initial datatype for binpac
######################################################################

type DTLSPDU(is_orig: bool) = record {
	records: SSLRecordSwitch(is_orig)[] &transient;
};

# This feels like (another) really dirty hack. DTLS 1.3 introduces a new way in which ciphertext records
# can be encoded, using a new unified header, which is completely different from the earlier DTLS headers.
# It only is used after the client & server hello - which essentially are the same as in DTLS 1.2 (including
# using the same record-layer versions - which is why `dtls_version_ok` underneath does not refer to DTLS 1.3)
# The DTLS 1.3 unified header is signaled by the first 3 bits of the first byte being set to `001`, but only
# after DTLS 1.3 has been negotiated.
type SSLRecordSwitch(is_orig: bool) = record {
	firstbyte: uint8;

	cont: case $context.connection.is_unified_record(firstbyte) of {
		false -> rec: SSLRecord(firstbyte, is_orig);
		true -> unified: UnifiedRecord(firstbyte, is_orig);
	};
};

type UnifiedRecord(firstbyte: uint8, is_orig: bool) = record {
	# If we have a CID, we do currently not try to parse anything, as the connection
	# ID is variable length, with the length not given in this packet (but only in the hello message
	# of the opposite side of the direction).
	seqnum: case with_cid of {
		false -> sequence_number: bytestring &length=(sequence_number_length?2:1);
		true -> nothing1: bytestring &length=0;
	} &requires(sequence_number_length) &requires(with_cid);
	lengthfield: case (with_cid == false && length_present == true) of {
		true -> length: uint16;
		false -> nothing2: bytestring &length=0;
	} &requires(length_present) &requires(with_cid);
	swallow: bytestring &restofdata;
} &let {
	with_cid: bool = ((firstbyte&0x10)==0x10);
	sequence_number_length: bool = ((firstbyte&0x08)==0x08);
	length_present: bool = ((firstbyte&0x04)==0x04);
	epoch_low_bits: uint8 = (firstbyte&0x03);
} &byteorder = bigendian;

type SSLRecord(content_type: uint8, is_orig: bool) = record {
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
			if ( zeek_analyzer()->AnalyzerConfirmed() )
				invalid_version_count_ = 0;
			return true;

		default:
			invalid_version_count_++;

			if ( zeek_analyzer()->AnalyzerConfirmed() )
				{
				reported_errors_++;
				if ( reported_errors_ <= zeek::BifConst::SSL::dtls_max_reported_version_errors )
					zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("Invalid version in DTLS connection. Packet reported version: %d", version));
				}

			if ( invalid_version_count_ > zeek::BifConst::SSL::dtls_max_version_errors )
				zeek_analyzer()->SetSkip(true);
			return false;
		}
		%}

		function is_unified_record(firstbyte: uint8): bool
			%{
			uint16_t negotiated_version = zeek_analyzer()->GetNegotiatedVersion();
			return negotiated_version == DTLSv13 && ( (firstbyte & 0xE0) == 0x20 );
			%}
};
