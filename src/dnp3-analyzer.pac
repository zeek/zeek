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
	#function get_dnp3_application_request_header(app_control: const_bytestring, fc: const_bytestring): bool
	function get_dnp3_application_request_header(app_control: uint8, fc: uint8): bool
               %{
               if ( ::dnp3_application_request_header )
                       {
                       BifEvent::generate_dnp3_application_request_header(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), 
				//bytestring_to_val( app_control ), 
				//bytestring_to_val( fc ) 
				app_control, 
				fc
				);
                       }
               return true;
               %}
        function get_dnp3_object_header(obj_type: uint16, qua_field: uint8): bool
               %{
               if ( ::dnp3_object_header )
                       {
                       BifEvent::generate_dnp3_object_header(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), obj_type, qua_field);
                       }

               return true;
               %}
	function get_dnp3_debug_byte(debug: const_bytestring): bool
               %{
               if ( ::dnp3_debug_byte )
                       {
                       BifEvent::generate_dnp3_debug_byte (
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), bytestring_to_val(debug) );
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

refine typeattr Dnp3_Application_Request_Header += &let {
       process_request: bool =  $context.flow.get_dnp3_application_request_header(application_control, function_code);
};

refine typeattr Object_Header += &let {
       process_request: bool =  $context.flow.get_dnp3_object_header(object_type_field, qualifier_field);
};


refine typeattr Debug_Byte += &let {
       process_request: bool =  $context.flow.get_dnp3_debug_byte(debug);
};







