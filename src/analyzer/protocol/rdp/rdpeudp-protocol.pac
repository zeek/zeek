
type RDPEUDP_PDU(is_orig: bool) = record {
	msg_type: case $context.flow.is_established() of {
		false -> no_established: case is_orig of {
			true ->  as_syn:	RDPEUDP1_SYN;
			false -> as_synack:	RDPEUDP1_SYNACK;
		};
		true -> yes_established: case $context.flow.is_rdpeudp2() of {
			true ->  as_ack2:	RDPEUDP2_ACK;
			false -> as_ack1: 	RDPEUDP1_ACK;
		};
	};
}&byteorder=bigendian;

type RDPEUDP1_SYN = record {
	fec_header: 	RDPUDP_FEC_HEADER;
	stub:		bytestring &restofdata;
} &let {
	seen_syn: bool = $context.flow.set_syn(fec_header.uFlags, fec_header.snSourceAck);
	is_rdpeudp: bool = $context.flow.set_rdpeudp2(fec_header.uFlags);
};

type RDPEUDP1_SYNACK = record {
	fec_header: 	RDPUDP_FEC_HEADER;
	stub:		bytestring &restofdata;
} &let {
	seen_synack: bool = $context.flow.set_synack(fec_header.uFlags);
};

type RDPEUDP2_ACK = record {
	stub:		bytestring &restofdata;
};

type RDPEUDP1_ACK = record {
	fec_header:	RDPUDP_FEC_HEADER;
	stub:		bytestring &restofdata;
};

type RDPUDP_FEC_HEADER = record {
        snSourceAck:		uint32;
        uReceiveWindowSize:	uint16;
        uFlags:			uint16;
};
