refine flow RDPEUDP_Flow += {
        %member{
		uint32 message_count = 0;
		enum RDPEUDP_STATE {
		        NEED_SYN	= 0x1,
		        NEED_SYNACK	= 0x2,
		        ESTABLISHED1	= 0x3,
		        ESTABLISHED2	= 0x4
		};
		uint8 state_ = NEED_SYN;
		bool is_rdpeudp2_ = false;
        %}

	function get_state(): uint8
	%{
		return this->state_;
	%}

        function proc_rdpeudp1_syn(is_orig: bool, uFlags: uint16, snSourceAck: uint32): bool
	%{
		this->message_count += 1;
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_syn", get_state(), 1, this->message_count);
		if (!is_orig) {
			return false;
		}
                if ((uFlags & 0x01) == 0) {
                        return false;
                }
		if (snSourceAck != 0xffffffff) {
			return false;
		}
		if (uFlags >= 0x1000) {
			is_rdpeudp2_ = true;
		}
                BifEvent::generate_rdpeudp_syn(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
		this->state_ = NEED_SYNACK;
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_syn", get_state(), 2, this->message_count);
                return true;
	%}

        function proc_rdpeudp1_synack(is_orig: bool, uFlags: uint16): bool
	%{
		this->message_count += 1;
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_synack", get_state(), 3, this->message_count);
		if (is_orig) {
			return false;
		}
		if ((uFlags & 0x05) == 0) {
			return false;
		}
                BifEvent::generate_rdpeudp_synack(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
                BifEvent::generate_rdpeudp_established(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());

		if (is_rdpeudp2_) {
			this->state_ = ESTABLISHED2;
		} else {
			this->state_ = ESTABLISHED1;
		}
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_synack", get_state(), 4, this->message_count);
                return true;
	%}

        function proc_rdpeudp2_ack(is_orig: bool): bool
	%{
		this->message_count += 1;
                BifEvent::generate_rdpeudp_data(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 2);
                return true;
	%}
        function proc_rdpeudp1_ack(is_orig: bool): bool
	%{
		this->message_count += 1;
                BifEvent::generate_rdpeudp_data(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 1);
                return true;
	%}

};
