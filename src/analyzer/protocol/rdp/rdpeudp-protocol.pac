# There are basically 5 PDU types
#  1. SYN - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/066f9acf-fd57-4f95-ab3f-334e748bab10
#  2. SYNACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/96eaa81a-ff42-40a2-884c-96b3834db6c8
#  3. ACK (bare) - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/facb0b31-63c6-44f4-aeec-03b5163aedae
#  4. ACK + FEC - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/7eaacd17-7012-468f-aa00-6e629cb88df8
#  5. ACK + Source - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/427c5d29-6b08-4cdb-bbdf-a1ed09e76e2d



enum RDPEUDP_STATE {
        NEED_SYN	= 0x1,
        NEED_SYNACK	= 0x2,
        ESTABLISHED	= 0x3,
};

type RDPEUDP_PDU(is_orig: bool) = record {
	state: case $context.connection.get_state() of {
		NEED_SYN 	->  need_syn:		RDPEUDP_SYN(this, is_orig);
		NEED_SYNACK 	->  need_synack:	RDPEUDP_SYNACK(this, is_orig);
		ESTABLISHED	->  est1:		RDPEUDP_ACK(this, is_orig);
	};
} &byteorder=bigendian;

type RDPEUDP_SYN(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header: 	RDPUDP_FEC_HEADER;
} &let {
	proc_rdpeudp_syn: bool = $context.connection.proc_rdpeudp_syn(is_orig, fec_header.uFlags, fec_header.snSourceAck);
};

type RDPEUDP_SYNACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header: 	RDPUDP_FEC_HEADER;
} &let {
	proc_rdpeudp_synack: bool = $context.connection.proc_rdpeudp_synack(is_orig, fec_header.uFlags);
};

enum RDPUDP_FLAG {
	RDPUDP_FLAG_SYN 	= 0x0001,
	RDPUDP_FLAG_FIN 	= 0x0002,
	RDPUDP_FLAG_ACK 	= 0x0004,
	RDPUDP_FLAG_DATA 	= 0x0008,
	RDPUDP_FLAG_FEC		= 0x0010,
	RDPUDP_FLAG_CN		= 0x0020,
	RDPUDP_FLAG_CWR		= 0x0040,
	RDPUDP_FLAG_SACK_OPTION	= 0x0080,
	RDPUDP_FLAG_ACK_OF_ACKS = 0x0100,
	RDPUDP_FLAG_SYNLOSSY	= 0x0200,
	RDPUDP_FLAG_ACKDELAYED 	= 0x0400,
	RDPUDP_FLAG_CORRELATION_ID = 0x800,
	RDPUDP_FLAG_SYNEX = 0x1000
};

type RDPEUDP_ACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header:		RDPUDP_FEC_HEADER;
	ack_vec_header:		RDPUDP_ACK_VECTOR_HEADER;
	ack_of_ackvec_header:	case fec_header.uFlags & RDPUDP_FLAG_ACK_OF_ACKS of {
		RDPUDP_FLAG_ACK_OF_ACKS -> some: 	RDPUDP_ACK_OF_ACKVECTOR_HEADER;
		default -> no_ack_of_ackvec_header:	empty;
	};
	# This doesn't handle ACK+FEC packets, which have both RDPUDP_FLAG_DATA and RDPUDP_FLAG_FEC set
	source_payload_header:	case (fec_header.uFlags & RDPUDP_FLAG_DATA) of {
		RDPUDP_FLAG_DATA -> some_source_payload:	RDPUDP_SOURCE_PAYLOAD_HEADER;
		default -> no_source_payload_header:		empty;
	};
	data:		bytestring &restofdata;
} &let {
	proc_rdpeudp_ack: bool = $context.connection.proc_rdpeudp_ack(is_orig, data);
};

type RDPUDP_SOURCE_PAYLOAD_HEADER = record {
	snCoded:	uint32;
	snSourceStart:	uint32;
};

type RDPUDP_ACK_OF_ACKVECTOR_HEADER = record {
	snAckOfAcksSeqNum:	uint32;
};

type RDPUDP_FEC_HEADER = record {
        snSourceAck:		uint32;
        uReceiveWindowSize:	uint16;
        uFlags:			uint16;
};

type RDPUDP_ACK_VECTOR_HEADER = record {
	uAckVectorSize:		uint16;
	AckVectorElement:	uint8[uAckVectorSize];
	pad:			padding align 4;
};
