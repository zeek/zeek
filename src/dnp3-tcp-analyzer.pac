# $Id:$
#
# This template code contributed by Kristin Stephens.

connection Dnp3TCP_Conn(bro_analyzer: BroAnalyzer) {
	upflow = Dnp3TCP_Flow(true);
	downflow = Dnp3TCP_Flow(false);
};

flow Dnp3TCP_Flow(is_orig: bool) {
	flowunit = Dnp3TCP_PDU withcontext (connection, this);

	function get_dnp3tcp_header_block(start: uint16, len: uint8, ctrl: uint8, dest_addr: uint16, src_addr: uint16, crc: uint16): bool
		%{
		if ( ::dnp3tcp_header_block )
			{
			BifEvent::generate_dnp3tcp_header_block(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), start, len, ctrl, dest_addr, src_addr, crc);
			}

		return true;
		%}
	function get_dnp3tcp_data_block(data: const_bytestring, crc: uint16): bool
		%{
		if ( ::dnp3tcp_data_block )
			{
			BifEvent::generate_dnp3tcp_data_block(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), bytestring_to_val(data), crc );
			}

		return true;
		%}
	function get_dnp3tcp_pdu(rest: const_bytestring): bool
		%{
		if ( ::dnp3tcp_pdu )
			{
			BifEvent::generate_dnp3tcp_pdu(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), bytestring_to_val(rest) );
			}

		return true;
		%}

};

refine typeattr Header_Block += &let {
        get_header: bool =  $context.flow.get_dnp3tcp_header_block(start, len, ctrl, dest_addr, src_addr, crc );
};
refine typeattr Data_Block += &let {
        get_data: bool =  $context.flow.get_dnp3tcp_data_block(data, crc );
};
refine typeattr Dnp3TCP_PDU += &let {
        get_pdu: bool =  $context.flow.get_dnp3tcp_pdu(rest );
};






