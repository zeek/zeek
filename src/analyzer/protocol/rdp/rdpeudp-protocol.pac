# There are basically 5 PDU types for RDUEUDP1
#  1. SYN - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/066f9acf-fd57-4f95-ab3f-334e748bab10
#  2. SYNACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/96eaa81a-ff42-40a2-884c-96b3834db6c8
#  3. ACK (bare) - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/facb0b31-63c6-44f4-aeec-03b5163aedae
#  4. ACK + FEC - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/7eaacd17-7012-468f-aa00-6e629cb88df8
#  5. ACK + Source - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/427c5d29-6b08-4cdb-bbdf-a1ed09e76e2d
# There is basically 1 PDU type for RDPEUDP2. It has a bunch of optional fields indicated by flags.


enum RDPEUDP_STATE {
	NEED_SYN	= 0x1,
	NEED_SYNACK	= 0x2,
	NEED_ACK	= 0x3,
	ESTABLISHED	= 0x4,
};

type RDPEUDP_PDU(is_orig: bool) = record {
	state: case $context.connection.get_state() of {
		NEED_SYN 	->  need_syn:		RDPEUDP_SYN(this, is_orig);
		NEED_SYNACK 	->  need_synack:	RDPEUDP_SYNACK(this, is_orig);
		NEED_ACK	->  need_ack:		RDPEUDP_ACK(this, is_orig);
		default		->  established:	RDPEUDP_ACK(this, is_orig);
	};
} &byteorder=bigendian;

type RDPEUDP_SYN(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header:	 	RDPUDP_FEC_HEADER;
	syndata_payload:	RDPUDP_SYNDATA_PAYLOAD;
	corr_id_payload:	case ((fec_header.uFlags & RDPUDP_FLAG_CORRELATION_ID) > 0) of {
		true -> has_corr_id_payload:		RDPUDP_CORRELATION_ID_PAYLOAD;
		false -> has_no_corr_id_payload:	empty;
	};
	synex_payload:		case ((fec_header.uFlags & RDPUDP_FLAG_SYNEX) > 0) of {
		true -> has_synex_payload:		RDPUDP_SYNEX_PAYLOAD;
		false -> has_no_synex_payload:		empty;
	};
} &let {
	proc_rdpeudp_syn: bool = $context.connection.proc_rdpeudp_syn(is_orig, fec_header.uFlags,
							fec_header.snSourceAck, has_synex_payload.uUdpVer);
};

# The tech specs refer to this as both RDPUDP_SYNEX_PAYLOAD and RDPUDP_SYNDATAEX_PAYLOAD
type RDPUDP_SYNEX_PAYLOAD = record {
	uSynExFlags:	uint16;
	uUdpVer:	uint16;
	cookieHash:	case (uUdpVer == RDPUDP_PROTOCOL_VERSION_3) of {
		true -> has_cookie_hash:	uint8[32];
		false -> has_no_cookie_hash:	empty;
	};
};

enum RDPUDP_VERSION_INFO_FLAG {
	RDPUDP_PROTOCOL_VERSION_1	= 0x0001,
	RDPUDP_PROTOCOL_VERSION_2	= 0x0002,
	RDPUDP_PROTOCOL_VERSION_3	= 0x0101
};

type RDPUDP_CORRELATION_ID_PAYLOAD = record {
	uCorrelationId:	uint8[16];
	uReserved:	uint8[16];
};

type RDPUDP_SYNDATA_PAYLOAD = record {
	snInitialSequenceNumber:	uint32;
	uUpStreamMtu:			uint16;
	uDownStreamMtu:			uint16;
};

type RDPEUDP_SYNACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header:	 	RDPUDP_FEC_HEADER;
	syndata_payload:	RDPUDP_SYNDATA_PAYLOAD;
	corr_id_payload:	case ((fec_header.uFlags & RDPUDP_FLAG_CORRELATION_ID) > 0) of {
		true -> has_corr_id_payload:		RDPUDP_CORRELATION_ID_PAYLOAD;
		false -> has_no_corr_id_payload:	empty;
	};
	synex_payload:		case ((fec_header.uFlags & RDPUDP_FLAG_SYNEX) > 0) of {
		true -> has_synex_payload:		RDPUDP_SYNEX_PAYLOAD;
		false -> has_no_synex_payload:		empty;
	};
} &let {
	proc_rdpeudp_synack: bool = $context.connection.proc_rdpeudp_synack(is_orig, fec_header.uFlags, has_synex_payload.uUdpVer);
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
	RDPUDP_FLAG_SYNEX 	= 0x1000
};

type RDPEUDP_ACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	version: case ($context.connection.is_rdpeudp2()) of {
		true ->	version2:	RDPEUDP2_ACK(pdu, is_orig);
		false -> version1:	RDPEUDP1_ACK(pdu, is_orig);
	};
};

type RDPEUDP1_ACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
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
	proc_rdpeudp1_ack: bool = $context.connection.proc_rdpeudp1_ack(is_orig, data);
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

# version 2
type RDPEUDP2_ACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	PacketPrefixByte:	uint8;
	header:			RDPUDP2_PACKET_HEADER;
# TODO:
#	ack_payload:		case ((header.Flags & ACK) > 0) of {
#		true -> has_ack_p:		RDPUDP2_ACK_PAYLOAD;
#		false -> has_no_ack_p:		empty;
#	};
#	oversize_payload:	case ((header.Flags & 0x040) > OVERHEADSIZE) of {
#		true -> has_oversize:		RDPUDP2_OVERSIZE_PAYLOAD;
#		false -> has_no_oversize:	empty;
#	};
#	delay_ack_info_payload:	case ((header.Flags & DELAYACKINFO) > 0) of {
#		true -> has_ack_info_p:		RDPUDP2_DELAYACKINFO_PAYLOAD;
#		false -> has_no_ack_info_p:	empty;
#	};
#	ack_of_acks_payload:	case ((header.Flags & AOA) > 0) of {
#		true -> has_aoa_p:            	RDPUDP2_ACKOFACKS_PAYLOAD;
#		false -> has_no_aoa_p:          empty;
#	};
#	data_header_payload:	case ((header.Flags & DATA) > 0) of {
#		true -> has_data_h:		RDPUDP2_DATAHEADER_PAYLOAD;
#		false -> has_no_data_h:		empty;
#	};
#	ack_vector_payload:	case ((header.Flags & ACKVEC) > 0) of {
#		true -> has_av_p:		RDPUDP2_ACKVECTOR_PAYLOAD;
#		false -> has_no_av_p:		empty;
#	};
#	data_body_payload:	case ((header.Flags & DATA) > 0) of {
#		true -> has_data_p:		RDPUDP2_DATABODY_PAYLOAD;
#		false -> has_no_data_p:		empty;
#	};
#	data_body_payload:			RDPUDP2_DATABODY_PAYLOAD;
	data: bytestring &restofdata;
} &let {
	Reserved:		uint8 = PacketPrefixByte & 0x80;
	Packet_Type_Index:	uint8 = PacketPrefixByte & 0x78;
	Short_Packet_Length:	uint8 = PacketPrefixByte & 0x07;
#	proc_rdpeudp2_ack: bool = $context.connection.proc_rdpeudp2_ack(is_orig, Packet_Type_Index, data_body_payload.Data);
	proc_rdpeudp2_ack: bool = $context.connection.proc_rdpeudp2_ack(is_orig, Packet_Type_Index, data);
};

type RDPUDP2_PACKET_HEADER = record {
	everything:	uint16;
} &let {
	Flags:		uint16 = everything & 0xfff0;   # The high 12
	LogWindowSize:	uint8 = everything &  0x000f;   # The low 4
};

enum RDPUDP2_PACKET_HEADER_FLAGS {
	ACK		= 0x001,
	DATA		= 0x004,
	ACKVEC		= 0x008,
	AOA		= 0x010,
	OVERHEADSIZE	= 0x040,
	DELAYACKINFO	= 0x100
};

type RDPUDP2_ACK_PAYLOAD = record {
	SeqNum:			uint16;
	tmp1:			uint32;
	tmp2:			uint8;
	delayAckTimeAdditions:	uint8[numDelayedAcks];
} &let {
	receivedTS:		uint8 = tmp1 & 0xffffff00;
	sendAckTimeGap:		uint8 = tmp1 & 0xff;
	numDelayedAcks: 	uint8 = tmp2 & 0xf0;   # top 4 bits
	delayAckTimeScale: 	uint8 = tmp2 & 0x0f;   # bottom 4 bits
};

type RDPUDP2_OVERSIZE_PAYLOAD = record{
	OverheadSize:	uint8;
};

type RDPUDP2_DATABODY_PAYLOAD = record {
	ChannelSeqNum:	uint16;
	Data:		bytestring &restofdata;
};

type RDPUDP2_ACKVECTOR_PAYLOAD = record {
	BaseSeqNum:		uint16;
	tmp1:			uint8;
	TimeStamp_or_not:	case TimeStampPresent of {
		0 -> none: 		empty;
		default -> some:	RDPUDP2_ACKVECTOR_PAYLOAD_TimeStamp;
	} &requires(TimeStampPresent);
	codedAckVector:		uint8[codedAckVecSize];
} &let {
	codedAckVecSize:	uint8 = tmp1 & 0xfe;
	TimeStampPresent:	uint8 = tmp1 & 0x01;
};

type RDPUDP2_ACKVECTOR_PAYLOAD_TimeStamp = record {
	tmp1: uint8;
	tmp2: uint8;
	tmp3: uint8;
} &let {
	TimeStamp: uint32 = tmp3 | (tmp2 << 8) | (tmp1 << 16);
};

type RDPUDP2_DATAHEADER_PAYLOAD = record {
	DataSeqNum:	uint16;
};

type RDPUDP2_ACKOFACKS_PAYLOAD = record {
	AckOfAcksSeqNum:	uint16;
};

type RDPUDP2_DELAYACKINFO_PAYLOAD = record {
	MaxDelayedAcks:		uint8;
	DelayedAckTimeoutInMs:	uint16;
};
