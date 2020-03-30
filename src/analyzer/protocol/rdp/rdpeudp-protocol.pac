# RDPEUDP connection states
enum RDPEUDP_STATE {
        NEED_SYN	= 0x1,
        NEED_SYNACK	= 0x2,
        ESTABLISHED1	= 0x3,
        ESTABLISHED2	= 0x4
};

type RDPEUDP_PDU(is_orig: bool) = record {
	state: case $context.connection.get_state() of {
		NEED_SYN 	->  need_syn:		RDPEUDP1_SYN(this, is_orig);
		NEED_SYNACK 	->  need_synack:	RDPEUDP1_SYNACK(this, is_orig);
		ESTABLISHED1	->  est1:		RDPEUDP1_ACK(this, is_orig);
		ESTABLISHED2	->  est2:		RDPEUDP2_ACK(this, is_orig);
	};
} &byteorder=bigendian;

# RDPEUDP version 1
type RDPEUDP1_SYN(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header: 	RDPUDP_FEC_HEADER(pdu);
	stub:		bytestring &restofdata;
} &let {
	proc_rdpeudp1_syn: bool = $context.connection.proc_rdpeudp1_syn(is_orig, fec_header.uFlags, fec_header.snSourceAck);
};

type RDPEUDP1_SYNACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header: 	RDPUDP_FEC_HEADER(pdu);
	stub:		bytestring &restofdata;
} &let {
	proc_rdpeudp1_synack: bool = $context.connection.proc_rdpeudp1_synack(is_orig, fec_header.uFlags);
};

# RDPEUDP1_ACK and RDPEUDP2_ACK assume data is piggybacked on the final ack of the 3-way handshake
type RDPEUDP1_ACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
#	fec_header:	RDPUDP_FEC_HEADER(pdu);
	stub:		bytestring &restofdata;
} &let {
	proc_rdpeudp1_ack: bool = $context.connection.proc_rdpeudp1_ack(is_orig, stub);
};

# This header is only used by version 1 PDUs of RDPEUDP
type RDPUDP_FEC_HEADER(pdu: RDPEUDP_PDU) = record {
        snSourceAck:		uint32;
        uReceiveWindowSize:	uint16;
        uFlags:			uint16;
};








# RDPEUDP version 2
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/98f1d4e7-b9ee-4434-97c0-72c88fdfaf27
type RDPEUDP2_ACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	header:			RDPUDP2_PACKET_HEADER;
	ack_payload:		case (header.Flags % 2) of {
		0 -> none:	empty;
		1 -> some:	RDPUDP2_ACK_PAYLOAD;
	};
	oversize_payload:	RDPUDP2_OVERSIZE_PAYLOAD;
	delay_ack_info_payload:	RDPUDP2_DELAYACKINFO_PAYLOAD;
	ack_of_acks_payload:	RDPUDP2_ACKOFACKS_PAYLOAD;
	data_header_payload:	RDPUDP2_DATAHEADER_PAYLOAD;
	ack_vector_payload:	RDPUDP2_ACKVECTOR_PAYLOAD;
	data_body_payload:	RDPUDP2_DATABODY_PAYLOAD;
} &let {
	proc_rdpeudp2_ack: bool = $context.connection.proc_rdpeudp2_ack(is_orig, data_body_payload.Data);
};

type RDPUDP2_PACKET_HEADER = record {
	# flags are 12 bits, A is 4 bits
	everything:	uint16;	
} &let {
	# Flags should be some combination of RDPUDP2_PACKET_HEADER_FLAGS
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









type RDPUDP2_PACKET_PREFIX_BYTE = record {
	everything:		uint8;
} &let {
	Reserved:		uint8 = everything & 128;	# The highest  bit
	# If Packet_Type_Index = 0 this is a real pkt. 
        # If Packet_Type_Index == 8, this is a dumby pkt. 
        # All other values should generate a weird
	Packet_Type_Index:	uint8 = everything & 120;	# The middle chunk, see the spec! 
	Short_Packet_Length:	uint8 = everything & 0x07;	# The low 3 bits
};

