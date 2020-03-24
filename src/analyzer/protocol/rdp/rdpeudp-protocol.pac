# SYN - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/ddc57322-08ae-48a5-a660-bd4aa676d8c9
# SYN+ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/0c66977c-a837-4f17-8a89-4a351866d86c
# DATA+ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/2ce2f61d-aa42-47f6-9fc9-8351d84a95c3  
# ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/bfa8ba8c-b23c-469b-984c-3d0288a21b50

type RDPEUDP_PDU(is_orig: bool) = record {
	data: bytestring &restofdata;
} &byteorder=bigendian;


# SYN messages require fec_header.uFlags == 0x0001
type RDPEUDP1_SYN() = record {
	fec_header: 		RDPUDP_FEC_HEADER;
	syn_data_payload:	RDPUDP_SYNDATA_PAYLOAD;
	correlation_id_payload:	RDPUDP_CORRELATION_ID_PAYLOAD;

	# This is optional and only present if the RDPUDP_FLAG_SYNEX flag is in the RDPUDP_FEC_HEADER's uFlags field.
        # That flag also indicates the client's preference to use RDPEUDP2 after the SYN and SYNACK messages.
	# TODO: figure out how to make this optional given a value of a member of fec_header
	syn_ex_payload:		RDPUDP_SYNDATAEX_PAYLOAD;

	pad:			padding align 1232;
}
# Somehow we need to use &let to set seen_syn_ to true

# SYNACK messages require fec_header.uFlags == 0x0005
type RDPEUDP1_SYNACK() = record {
	fec_header: 		RDPUDP_FEC_HEADER;
	syn_data_payload:	RDPUDP_SYNDATA_PAYLOAD;
	correlation_id_payload:	RDPUDP_CORRELATION_ID_PAYLOAD;

	# This is optional and only present if the RDPUDP_FLAG_SYNEX flag is in the RDPUDP_FEC_HEADER's uFlags field.
        # That flag also indicates the client's preference to use RDPEUDP2 after the SYN and SYNACK messages.
	# TODO: figure out how to make this optional given a value of a member of fec_header
	syn_ex_payload:		RDPUDP_SYNDATAEX_PAYLOAD;

	pad:			padding align 1232;	
}
# Somehow we need to use &let to set seen_ack_ to true, which also means is_established() now returns true.

# The SYN and SYNACK messages will determine if the subsiquent messages will be RDPEUDP or RDPEUDP2
type RDPEUDP2_ACK() = record {
	packet_prefix_byte:	RDPUDP2_PacketPrefixByte;
	header:			RDPUDP2_PACKET_HEADER;
	ack_payload:		RDPUDP2_ACK_PAYLOAD;
	oversize_flag:		RDPUDP2_OVERSIZE_PAYLOAD_FLAG;
	delay_ack_info_payload:	RDPUDP2_DELAYACKINFO_PAYLOAD;
	ack_of_acks_payload:	RDPUDP2_ACKOFACKS_PAYLOAD;
	data_header_payload:	RDPUDP2_DATAHEADER_PAYLOAD;
	ack_vector_payload:	RDPUDP2_ACKVECTOR_PAYLOAD;
	data_body_payload:	RDPUDP2_DATABODY_PAYLOAD;
}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/1c321fab-69c2-4ac2-9991-7306a3ec2ac5
type RDPUDP2_DATABODY_PAYLOAD() = record {}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/43183820-771d-4a00-89d6-58a3ecc80a78 
type RDPUDP2_ACKVECTOR_PAYLOAD() = record {}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/e2b9d0e8-44af-4b41-a71c-09747612f764
type RDPUDP2_DATAHEADER_PAYLOAD() = record {}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/478e60bb-b6ae-451e-8f9c-6f86bd9afb9a
type RDPUDP2_ACKOFACKS_PAYLOAD() = record {}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/eecd9c22-8d0b-4666-ae35-04b2f1ddea20
type RDPUDP2_DELAYACKINFO_PAYLOAD() = record {}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/7a5ec2cf-c0c1-4eef-8e13-ce87fae503f9
type RDPUDP2_OVERSIZE_PAYLOAD_FLAG() = record{}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/bf47de96-832e-45c7-974f-87d99d8d0fea
type RDPUDP2_ACK_PAYLOAD() = record {}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp2/80584a33-e430-43a3-871b-2f63abef7813
type RDPUDP2_PacketPrefixByte() = record {
	everything:		uint8;
} &let {
	Reserved:		uint8 = everything & 128; # The highest  bit

	# If Packet_Type_Index = 0 this is a real pkt. If Packet_Type_Index == 8, this is a dumby pkt. All other values shouold be weirds
	Packet_Type_Index:	uint8 = everything & 120; # The middle chunk, see the spec! 
	Short_Packet_Length:	uint8 = everything & 0x07; # The low 3 bits
}

enum RDPUDP2_PACKET_HEADER_FLAGS {
	ACK		= 0x001,
	DATA		= 0x004,
	ACKVEC		= 0x008,
	AOA		= 0x010,
	OVERHEADSIZE	= 0x040,
	DELAYACKINFO	= 0x100
}

type RDPUDP2_PACKET_HEADER() = record {
	# flags are 12 bits, A is 4 bits
	everything:	uint16;	
} &let {
	# Flags should be some combination of RDPUDP2_PACKET_HEADER_FLAGS
	Flags:		uint16 = everything >> 4;   # The high 12
	LogWindowSize:	uint8 = everything &  0x0f; # The low 4
}

# ACK messages can be pure ACK or can carry a payload.
# Payloads can be of type DATA (or Source Packet as the specs call it) or FEC
type RDUEUDP1_ACK() = record {
	fec_header:			RDPUDP_FEC_HEADER;
	ack_vector_header:		RDPUDP_ACK_VECTOR_HEADER;
	ack_of_ack_vector_header:	RDPUDP_ACK_OF_ACKVECTOR_HEADER;
	# The source payload and its header is optional and makes and ACK message a DATA+ACK message
	source_payload_header:		RDPUDP_SOURCE_PAYLOAD_HEADER;
	source_payload:			bytestring &restofdata;
}

type RDPUDP_SOURCE_PAYLOAD_HEADER() = record {
	snCoded:	uint32;
	snSourceStart:	uint32;
}

type RDPUDP_ACK_VECTOR_HEADER() = record {
	# uAckVectorSize must be less than 2048
	uAckVectorSize:		uint16;
	# THis is waaaay wrong but I'm not sure how to do arrays just yet
	AckVectorElement:	uint32[0];
	pad:			padding align 4;	# must be a DWORD boundary
}

type RDPUDP_ACK_OF_ACKVECTOR_HEADER() = record {
	snAckOfAcksSeqNum:	uint32;
}

enum RDPUDP_PROTOCOL_VERSION {
	RDPUDP_PROTOCOL_VERSION_1 = 0x0001,  # RDPEUDP
	RDPUDP_PROTOCOL_VERSION_2 = 0x0002,  # RDPEUDP
	RDPUDP_PROTOCOL_VERSION_3 = 0x0101   # RDPEUDP2
};

enum RDPUDP_SYN_EX_FLAG {
	RDPUDP_VERSION_INFO_VALID = 0x0001,
};

enum RDPUDP_FEC_FLAG {
	RDPUDP_FLAG_SYN = 0x0001,
	RDPUDP_FLAG_FIN = 0x0002,
	RDPUDP_FLAG_ACK = 0x0004,
	RDPUDP_FLAG_DATA = 0x0008,
	RDPUDP_FLAG_FEC = 0x0010,
	RDPUDP_FLAG_CN = 0x0020,
	RDPUDP_FLAG_CWR = 0x0040,
	RDPUDP_FLAG_SACK_OPTION = 0x0080,
	RDPUDP_FLAG_ACK_OF_ACKS  = 0x0100,
	RDPUDP_FLAG_SYNLOSSY = 0x0200,
	RDPUDP_FLAG_ACKDELAYED = 0x0400,
	RDPUDP_FLAG_CORRELATION_ID = 0x800,
	RDPUDP_FLAG_SYNEX = 0x1000
};

type RDPUDP_FEC_HEADER() = record {
        snSourceAck:            uint32;
        uReceiveWindowSize:     uint16;
        uFlags:                 uint16;
}

type RDPUDP_CORRELATION_ID_PAYLOAD() = record {
	uCorrelationId:	uint16;
	uReserved:	uint16;
}

type RDPUDP_SYNDATA_PAYLOAD() = record {
	snInitialSequenceNumber:	uint32;
	uUpStreamMtu:			uint16;
	uDownStreamMtu:			uint16;
}

type RDPUDP_SYNDATAEX_PAYLOAD() = record {
	uSynExFlags:	uint16;
	uUdpVer:	uint16;
	cookieHash:	bytestring &length=32;
}

refine connection RDPEUDP_Conn += {
        %member{
		bool seen_syn_;
		bool seen_synack_;
		bool is_rdpeudp2_;
        %}

        %init{
		seen_syn_ = false;
		seen_synack_ = false;
		is_rdpeudp2_ = false;
        %}

        function is_rdpeudp2(): bool
	%{
                return is_rdpeudp2_;
	%}

        function seen_syn(): bool
	%{
                return seen_syn_;
	%}
        function seen_synack(): bool
	%{
                return seen_synack_;
	%}

        function is_established(): bool
	%{
                return seen_syn_ && seen_synack_;
	%}
};
