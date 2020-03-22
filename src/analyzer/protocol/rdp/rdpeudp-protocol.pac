# SYN - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/ddc57322-08ae-48a5-a660-bd4aa676d8c9
# SYNACK - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/0c66977c-a837-4f17-8a89-4a351866d86c

type RDPEUDPPDU_SYN() = record {
	RDPEUDP_FEC_HEADER:		?;
	RDPEUDP_SYNDATA_PAYLOAD: 	?;
	RDPEUDP_CORRELATION_ID_PAYLOAD:	?;
}

type RDPEUDPPDU_SYNACK() = record {
        RDPEUDP_FEC_HEADER:              ?;
        RDPEUDP_SYNDATA_PAYLOAD:         ?;
}

type RDPEUDP_FEC_HEADER() = record {
	snSourceAck:		uint32;
	uReceiveWindowSize:	uint16;
	uFlags:			uint16;
}

type RDPEUDP_SYNDATA_PAYLOAD() = record {
	snInitialSequenceNumber:	uint32;
	uUpStreamMtu:			uint16;
	uDownStreamMtu:			uint16;
}

type RDPEUDP_CORRELATION_ID_PAYLOAD() = record {
	uCorrelationId:	?;
	uReserved: 	?;
	pad: 		bytestring &length=?; # This needs to be padded to 1232 bytes
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
