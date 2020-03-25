# client sends RDPEUDP SYN
# server sendds RDPEUDP SYNACK
# client sends TLS or DTLS records wrapped in RDPEUDP or RDPEUDP2, depending on what was negotiated in the handshake
# server sends TLS or DTLS records wrapped in same framing as client
# for now, it'd be great TODO:
#  1. pass the client and server TLS records to the SSL analyzer
#  2. raise an "event rdpeudp_established(c: connection)"

refine flow RDPEUDP_Flow += {
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


refine typeattr RDPEUDP_PDU += &let {
	set_rdpeudp2: bool = $context.flow.set_rdpeudp2();
	is_rdpeudp2: bool = $context.flow.is_rdpeudp2();
	seen_syn: bool = $context.flow.seen_syn();
	seen_synack: bool = $context.flow.seen_synack();
	set_syn: bool = $context.flow.set_syn();
	set_synack: bool = $context.flow.set_synack();
	is_established: bool = $context.flow.is_established();
};

