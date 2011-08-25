# $Id:$
#
# This template code contributed by Kristin Stephens.

connection Dnp3_Conn(bro_analyzer: BroAnalyzer) {
	upflow = Dnp3_Flow(true);
	downflow = Dnp3_Flow(false);
};

flow Dnp3_Flow(is_orig: bool) {
	flowunit = Dnp3_PDU(is_orig) withcontext (connection, this);

	function get_dnp3_header_block(start: uint16, len: uint8, ctrl: uint8, dest_addr: uint16, src_addr: uint16): bool
		%{
		if ( ::dnp3_header_block )
			{
			BifEvent::generate_dnp3_header_block(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), start, len, ctrl, dest_addr, src_addr);
			}

		return true;
		%}
	function get_dnp3_data_block(data: const_bytestring, crc: uint16): bool
		%{
		if ( ::dnp3_data_block )
			{
			BifEvent::generate_dnp3_data_block(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), bytestring_to_val(data), crc );
			}

		return true;
		%}
	function get_dnp3_pdu_test(rest: const_bytestring): bool
		%{
		if ( ::dnp3_pdu_test )
			{
			BifEvent::generate_dnp3_pdu_test(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), bytestring_to_val(rest) );
			}

		return true;
		%}

};

refine typeattr Header_Block += &let {
        get_header: bool =  $context.flow.get_dnp3_header_block(start, len, ctrl, dest_addr, src_addr);
};
refine typeattr Data_Block += &let {
        get_data: bool =  $context.flow.get_dnp3_data_block(data, crc );
};
#refine typeattr Dnp3_PDU += &let {
#        get_pdu: bool =  $context.flow.get_dnp3_pdu(rest );
#};
refine typeattr Dnp3_Test += &let {
        get_pdu: bool =  $context.flow.get_dnp3_pdu_test(rest );
};








