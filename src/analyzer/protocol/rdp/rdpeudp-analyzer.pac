refine connection RDPEUDP_Conn += {
	%member{
		uint32 message_count = 0;
		enum RDPEUDP_STATE {
		        NEED_SYN	= 0x1,
		        NEED_SYNACK	= 0x2,
		        ESTABLISHED1	= 0x3,
		        ESTABLISHED2	= 0x4
		};
		uint8 state_ = NEED_SYN;
		bool is_encrypted_ = false;
		bool is_rdpeudp2_ = false;
	%}
	function get_state(): uint8
	%{
		return state_;
	%}

        function proc_rdpeudp1_syn(is_orig: bool, uFlags: uint16, snSourceAck: uint32): bool
	%{
		message_count += 1;
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_syn", get_state(), 1, message_count);
		if (!is_orig) {
			printf("    %s, state: %d, id: %d, count: %d\n",
				"proc_rdpeudp1_syn returning F because pkt is from responder",
				get_state(), 1003, message_count);		
			return false;
		}
                if ((uFlags & 0x01) == 0) {
			printf("    %s, state: %d, id: %d, count: %d\n",
				"proc_rdpeudp1_syn returning F because pkt does not have SYN flag set",
				get_state(), 1005, message_count);		
                        return false;
                }
		if (snSourceAck != 0xffffffff) {
			printf("    %s, state: %d, id: %d, count: %d\n",
				"proc_rdpeudp1_syn exiting because pkt does not start with ffffffff",
				get_state(), 1007, message_count);		
			return false;
		}
		if (uFlags >= 0x1000) {
			is_rdpeudp2_ = true;
		}
                BifEvent::generate_rdpeudp_syn(bro_analyzer(), bro_analyzer()->Conn());
		state_ = NEED_SYNACK;
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_syn", get_state(), 2, message_count);
                return true;
	%}

        function proc_rdpeudp1_synack(is_orig: bool, uFlags: uint16): bool
	%{
		message_count += 1;
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_synack", get_state(), 3, message_count);

		// It seems binpac never sets is_orig to false if the UDP is localhost <-> localhost
		if (is_orig) {
			printf("    %s, state: %d, id: %d, count: %d\n",
				"proc_rdpeudp1_synack returning F becayse pkt was from orig",
				get_state(), 99, message_count);
			return false;
		}

		if ((uFlags & 0x05) == 0) {
			printf("    %s, state: %d, id: %d, count: %d\n",
				"proc_rdpeudp1_synack returning F because SYNACK flags not set",
				get_state(), 98, message_count);
			return false;
		}
                BifEvent::generate_rdpeudp_synack(bro_analyzer(), bro_analyzer()->Conn());
                BifEvent::generate_rdpeudp_established(bro_analyzer(), bro_analyzer()->Conn());

		if (is_rdpeudp2_) {
			state_ = ESTABLISHED2;
		} else {
			state_ = ESTABLISHED1;
		}
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_synack", get_state(), 4, message_count);
                return true;
	%}

        function proc_rdpeudp2_ack(is_orig: bool, stub: bytestring): bool
	%{
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp2_ack", get_state(), 55, message_count);
		message_count += 1;
                BifEvent::generate_rdpeudp_data(bro_analyzer(),
						bro_analyzer()->Conn(),
						is_orig,
						2,
						new StringVal(stub.length(), (const char*) stub.data())
		);
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp2_ack", get_state(), 57, message_count);
                return true;
	%}
        function proc_rdpeudp1_ack(is_orig: bool, stub: bytestring): bool
	%{
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_ack", get_state(), 49, message_count);
		message_count += 1;
                BifEvent::generate_rdpeudp_data(bro_analyzer(),
						bro_analyzer()->Conn(),
						is_orig,
						1,
						new StringVal(stub.length(), (const char*) stub.data())
		);
		printf("inside %s, state: %d, id: %d, count: %d\n",
			"proc_rdpeudp1_ack", get_state(), 50, message_count);
                return true;
	%}
};
