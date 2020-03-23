# SYN - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/ddc57322-08ae-48a5-a660-bd4aa676d8c9
# SYN+ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/0c66977c-a837-4f17-8a89-4a351866d86c
# DATA+ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/2ce2f61d-aa42-47f6-9fc9-8351d84a95c3  
# ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/bfa8ba8c-b23c-469b-984c-3d0288a21b50

type RDPEUDP_PDU(is_orig: bool) = record {
	data: bytestring &restofdata;
} &byteorder=bigendian;

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
                bool is_established_;
        %}

        %init{
                is_established_ = false;
        %}

        function is_established(): bool
	%{
                return is_established_;
	%}
};

