refine connection RDPEUDP_Conn += {
	%member{
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
		return state_;
	%}

        function proc_rdpeudp1_syn(is_orig: bool, uFlags: uint16, snSourceAck: uint32): bool
	%{
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
                BifEvent::generate_rdpeudp_syn(bro_analyzer(), bro_analyzer()->Conn());
		state_ = NEED_SYNACK;
                return true;
	%}

        function proc_rdpeudp1_synack(is_orig: bool, uFlags: uint16): bool
	%{
		if (is_orig) {
			return false;
		}

		if ((uFlags & 0x05) == 0) {
			return false;
		}
                BifEvent::generate_rdpeudp_synack(bro_analyzer(), bro_analyzer()->Conn());

		if (is_rdpeudp2_) {
			state_ = ESTABLISHED2;
	                BifEvent::generate_rdpeudp_established(bro_analyzer(), bro_analyzer()->Conn(), 2);
		} else {
			state_ = ESTABLISHED1;
        	        BifEvent::generate_rdpeudp_established(bro_analyzer(), bro_analyzer()->Conn(), 1);
		}
                return true;
	%}

        function proc_rdpeudp2_ack(is_orig: bool, stub: bytestring): bool
	%{
                BifEvent::generate_rdpeudp_data(bro_analyzer(),
						bro_analyzer()->Conn(),
						is_orig,
						2,
						new StringVal(stub.length(), (const char*) stub.data())
		);
                return true;
	%}
        function proc_rdpeudp1_ack(is_orig: bool, stub: bytestring): bool
	%{
                BifEvent::generate_rdpeudp_data(bro_analyzer(),
						bro_analyzer()->Conn(),
						is_orig,
						1,
						new StringVal(stub.length(), (const char*) stub.data())
		);
                return true;
	%}
};
