# SYN - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/ddc57322-08ae-48a5-a660-bd4aa676d8c9
# SYN+ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/0c66977c-a837-4f17-8a89-4a351866d86c
# DATA+ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/2ce2f61d-aa42-47f6-9fc9-8351d84a95c3  
# ACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/bfa8ba8c-b23c-469b-984c-3d0288a21b50

type RDPEUDPPDU_SYN() = record {
	RDPEUDP_FEC_HEADER:		?;
	RDPEUDP_SYNDATA_PAYLOAD: 	?;
	RDPEUDP_CORRELATION_ID_PAYLOAD:	?;
	pad:				bytestring &length=?; # This needs to be padded to 1232 bytes
}

type RDPEUDPPDU_DATA_ACK() = record {
	RDPEUDP_FEC_HEADER:		?;
	RDPUDP_SOURCE_PAYLOAD_HEADER:	?;
}

type RDPEUDPPDU_SYN_ACK() = record {
        RDPEUDP_FEC_HEADER:		?;
        RDPEUDP_SYNDATA_PAYLOAD:	?;
	pad:				bytestring &length=?; # This needs to be padded to 1232 bytes
}

type RDPUDP_SOURCE_PAYLOAD_HEADER() = record {
	snCoded:		?;
	snSourceStart:		?;
	payload:		bytestring;
} &let {
	# The first and second RDPEUDPPDU_DATAs contains the SSL/DTLS handshake
	payload = rest of datagram;
}

type RDPEUDP_FEC_HEADER() = record {
	snSourceAck:		uint32;
	uReceiveWindowSize:	uint16;
	uFlags:			uint16;
	AckVector:		?;
	Size:			?;
	...
}

type RDPEUDP_SYNDATA_PAYLOAD() = record {
	snInitialSequenceNumber:	uint32;
	uUpStreamMtu:			uint16;
	uDownStreamMtu:			uint16;
}

type RDPEUDP_CORRELATION_ID_PAYLOAD() = record {
	uCorrelationId:	?;
	uReserved: 	?;
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
