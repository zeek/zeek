refine flow RDPEUDP_Flow += {
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

        function set_syn(uFlags: uint16, snSourceAck: uint32): bool
	%{
                if (!uFlags & 0x01) {
                        return false;
                }
		if (snSourceAck != 0xffffffff) {
			return false;
		}
                BifEvent::generate_rdpeudp_syn(bro_analyzer(), bro_analyzer()->Conn());
		seen_syn_ = true;
                return seen_syn_;
	%}

        function set_synack(uFlags: uint16): bool
	%{
		if (!seen_syn()) {
			return seen_synack_;
		}
		if (uFlags % 5 > 0) {
			return seen_synack_;
		}
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
