
######################################################################
# initial datatype for binpac
######################################################################

type DTLSPDU(is_orig: bool) = record {
	records: SSLRecord(is_orig)[] &transient;
};

type SSLRecord(is_orig: bool) = record {
	content_type: uint8;
	version: uint16;
	epoch: uint16;
	sequence_number: uint48;
	length: uint16;
	rec: PlaintextRecord(this)[] &length=length;
#	data: bytestring &restofdata &transient;
} &byteorder = bigendian,
	&let {
	parse : bool = $context.connection.proc_dtls(this, to_int()(sequence_number));
};

type Handshake(rec: SSLRecord) = record {
	msg_type: uint8;
	length: uint24;
	message_seq: uint16;
	fragment_offset: uint24;
	fragment_length: uint24;
}

refine connection SSL_Conn += {

	function proc_dtls(pdu: SSLRecord, sequence: uint64): bool
	%{
		fprintf(stderr, "Type: %d, sequence number: %d, epoch: %d\n", ${pdu.content_type}, sequence, ${pdu.epoch});

		return true;
	%}

};
