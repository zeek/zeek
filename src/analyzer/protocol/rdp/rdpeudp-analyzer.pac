refine flow RDPEUDP_Flow += {
        %member{
		RDPEUDP_STATE state_;
		bool is_rdpeudp2_;
        %}

        %init{
		state_ = NEED_SYN;
		is_rdpeudp2_ = false;
        %}

	function get_state(): RDPEUDP_STATE
	%{
		return state_;
	%}

        function proc_rdpeudp_syn(uFlags: uint16, snSourceAck: uint32): bool
	%{
                if ((uFlags & 0x01) == 0) {
			printf("this is not a syn pkt\n");
                        return false;
                }
		if (snSourceAck != 0xffffffff) {
			printf("this is not a syn pkt\n");
			return false;
		}
		if (uFlags >= 0x1000) {
			printf("this is rdpeudp2\n");
			is_rdpeudp2_ = true;
		}
		printf("this is a syn pkt\n");
                BifEvent::generate_rdpeudp_syn(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
		state_ = NEED_SYNACK;
                return true;
	%}

        function proc_rdpeudp1_synack(uFlags: uint16): bool
	%{
		if (uFlags % 5 > 0) {
			printf("this is not a synack pkt\n");
			return false;
		}
		printf("this is a synackc pkt\n");
                BifEvent::generate_rdpeudp_synack(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
                BifEvent::generate_rdpeudp_established(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());

		if (is_rdpeudp2_) {
			state_ = ESTABLISHED2;
		} else {
			state_ = ESTABLISHED1;
		}
                return true;
	%}

        function proc_rdpeudp2_ack(): bool
	%{
		printf("this is a rdpeudp2_ack message\n");
                return true;
	%}
        function proc_rdpeudp1_ack(): bool
	%{
		printf("this is a rdpeudp1_ack message\n");
                return true;
	%}

};
