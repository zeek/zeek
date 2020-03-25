type RDPEUDP_PDU(is_orig: bool) = record {
	msg_type: case $context.connection.is_established() of {
		false -> no_established: case (is_orig) of {
			true ->  as_syn:	RDPEUDP1_SYN;
			false -> as_synack:	RDPEUDP1_SYNACK;
		};
		true -> yes_established: case $context.connection.is_rdpeudp2() of {
			true ->  as_ack2:	RDPEUDP2_ACK;
			false -> as_ack1: 	RDPEUDP1_ACK;
		};
	};
} &byteorder=bigendian;

type RDPEUDP1_SYN = record {
	fec_header: 	RDPUDP_FEC_HEADER;
	stub:		bytestring &restofdata &transient;
} &let {
	seen_syn: bool = $context.connection.set_syn();
	is_rdpeudp: bool = $context.connection.set_rdpeudp2(fec_header.uFlags);
};

type RDPEUDP1_SYNACK = record {
	fec_header: 	RDPUDP_FEC_HEADER;
	stub:		bytestring &restofdata &transient;
} &let {
	seen_synack: bool = $context.connection.set_synack();
};

type RDPEUDP2_ACK = record {
	stub:		bytestring &restofdata &transient;
};

type RDPEUDP1_ACK = record {
	fec_header:	RDPUDP_FEC_HEADER;
	stub:		bytestring &restofdata &transient;
};

type RDPUDP_FEC_HEADER = record {
        snSourceAck:		uint32;
        uReceiveWindowSize:	uint16;
        uFlags:			uint16;
};

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

        function set_rdpeudp2(uFlags: uint16): bool
	%{
		if (uFlags >= 0x1000) {
			is_rdpeudp2_ = true;
		}
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

        function set_syn(): bool
	%{
                BifEvent::generate_rdpeudp_syn(bro_analyzer(), bro_analyzer()->Conn());
		seen_syn_ = true;
                return seen_syn_;
	%}

        function set_synack(): bool
	%{
                BifEvent::generate_rdpeudp_synack(bro_analyzer(), bro_analyzer()->Conn());
                BifEvent::generate_rdpeudp_established(bro_analyzer(), bro_analyzer()->Conn());
		seen_synack_ = true;
                return seen_synack_;
	%}

        function is_established(): bool
	%{
                return seen_syn_ && seen_synack_;
	%}
};
