refine connection RDPEUDP_Conn += {
	%member{
		enum RDPEUDP_STATE {
			NEED_SYN	= 0x1,
			NEED_SYNACK	= 0x2,
			NED_ACK		= 0x3,
			ESTABLISHED	= 0x4,
		};
		enum RDPUDP_VERSION_INFO_FLAG {
		        RDPUDP_PROTOCOL_VERSION_1       = 0x0001,
		        RDPUDP_PROTOCOL_VERSION_2       = 0x0002,
		        RDPUDP_PROTOCOL_VERSION_3       = 0x0101
		};
		uint8 state_ = NEED_SYN;
		uint16 orig_synex_flags_ = RDPUDP_PROTOCOL_VERSION_1;
		uint16 resp_synex_flags_ = RDPUDP_PROTOCOL_VERSION_1;
		bool orig_lossy_ = false;
		bool resp_lossy_ = false;
	%}

	function get_state(): uint8
		%{
		return state_;
		%}

	function is_rdpeudp2(): bool
		%{
		return ((orig_synex_flags_ & resp_synex_flags_) >= RDPUDP_PROTOCOL_VERSION_3);
		%}

	function proc_rdpeudp_syn(is_orig: bool, uFlags: uint16, snSourceAck: uint32, uUdpVer: uint16): bool
		%{
		if ( ! is_orig )
			return false;

		if ( (uFlags & 0x01) == 0 )
			return false;

		if ( snSourceAck != 0xffffffff )
			return false;

		orig_synex_flags_ = uUdpVer;

		if ( (uFlags & 0x0200) == 0x0200 )
			orig_lossy_ = true;

		if ( rdpeudp_syn )
			BifEvent::generate_rdpeudp_syn(bro_analyzer(), bro_analyzer()->Conn());

		state_ = NEED_SYNACK;
		return true;
		%}

	function proc_rdpeudp_synack(is_orig: bool, uFlags: uint16): bool
		%{
		if ( is_orig )
			return false;

		if ( (uFlags & 0x05) == 0 )
			return false;

		if ( rdpeudp_synack )
			BifEvent::generate_rdpeudp_synack(bro_analyzer(), bro_analyzer()->Conn());

		bro_analyzer()->ProtocolConfirmation();
		state_ = NEED_ACK;

		if ( uFlags >= 0x1000 )
			resp_synex_flags_ = 0x0101;

		if ( (uFlags & 0x0200) == 0x0200 )
			resp_lossy_ = true;

		return true;
		%}

	function proc_rdpeudp1_ack(is_orig: bool, data: bytestring): bool
		%{
		if ( state_ == NEED_ACK )
			{
			state_ = ESTABLISHED;

			if ( rdpeudp_established )
				BifEvent::generate_rdpeudp_established(bro_analyzer(), bro_analyzer()->Conn(), 1);
			}

		if ( state_ == ESTABLISHED && rdpeudp_data )
			BifEvent::generate_rdpeudp_data(bro_analyzer(),
							bro_analyzer()->Conn(),
							is_orig,
							1,
							bytestring_to_val(data)
			);

		return true;
		%}

	function proc_rdpeudp2_ack(is_orig: bool, pkt_type: uint8, data: bytestring): bool
		%{
		if ( pkt_type == 8 )
			// This is a "dummy packet".
			return false;

		if ( state_ == NEED_ACK )
			{
			if ( rdpeudp_established )
				BifEvent::generate_rdpeudp_established(bro_analyzer(), bro_analyzer()->Conn(), 2);

			state_ = ESTABLISHED;
			}

		if ( state_ == ESTABLISHED && rdpeudp_data )
			BifEvent::generate_rdpeudp_data(bro_analyzer(),
							bro_analyzer()->Conn(),
							is_orig,
							2,
							bytestring_to_val(data)
			);

		return true;
		%}
};
