enum RDPEUDP_STATE {
        NEED_SYN,
        NEED_SYNACK,
	ESTABLISHED1,
	ESTABLISHED2
};

type RDPEUDP_PDU(is_orig: bool) = record {
	state: case $context.connection.get_state() of {
		NEED_SYN 	->  need_syn:		RDPEUDP1_SYN(this, is_orig);
		NEED_SYNACK 	->  need_synack:	RDPEUDP1_SYNACK(this, is_orig);
		ESTABLISHED1	->  est1:		RDPEUDP1_ACK(this, is_orig);
		ESTABLISHED2	->  est2:		RDPEDUP2_ACK(this, is_orig);
	};
}&byteorder=bigendian;

type RDPEUDP1_SYN(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header: 	RDPUDP_FEC_HEADER(pdu);
	stub:		bytestring &restofdata &transient;
} &let {
	proc_rdpeudp1_syn: bool = $context.flow.proc_rdpeudp1_syn(fec_header.uFlags, fec_header.snSourceAck);
};

type RDPEUDP1_SYNACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header: 	RDPUDP_FEC_HEADER(pdu);
	stub:		bytestring &restofdata &transient;
} &let {
	proc_rdpeudp1_synack: bool = $context.flow.proc_rdpeudp1_synack(fec_header.uFlags);
};

type RDPEUDP2_ACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	stub:		bytestring &restofdata &transient;
} &let {
	proc_rdpeudp2_ack: bool = $context.flow.proc_rdpeudp2_ack();
};

type RDPEUDP1_ACK(pdu: RDPEUDP_PDU, is_orig: bool) = record {
	fec_header:	RDPUDP_FEC_HEADER(pdu);
	stub:		bytestring &restofdata &transient;
} &let {
	proc_rdpeudp1_ack: bool = $context.flow.proc_rdpeudp1_ack();
};

type RDPUDP_FEC_HEADER(pdu: RDPEUDP_PDU) = record {
        snSourceAck:		uint32;
        uReceiveWindowSize:	uint16;
        uFlags:			uint16;
};
