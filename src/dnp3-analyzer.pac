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
	function get_dnp3_application_response_header(app_control: uint8, fc: uint8): bool
               %{
               if ( ::dnp3_application_response_header )
                       {
                       BifEvent::generate_dnp3_application_response_header(
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
       function get_dnp3_object_header(obj_type: uint16, qua_field: uint8, number: uint32 ): bool
               %{
               if ( ::dnp3_object_header )
                       {
                       BifEvent::generate_dnp3_object_header(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), obj_type, qua_field, number);
                       }

               return true;
               %}
	function get_dnp3_data_object(data_value: uint8): bool
               %{
               if ( ::dnp3_data_object )
                       {
                       BifEvent::generate_dnp3_data_object(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), data_value);
                       }

               return true;
               %}
	function get_dnp3_analog_input32_woTime(flag: uint8, value: uint32): bool
               %{
               if ( ::dnp3_analog_input32_woTime )
                       {
                       BifEvent::generate_dnp3_analog_input32_woTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value);
                       }

               return true;
               %}
	function get_dnp3_analog_input16_woTime(flag: uint8, value: uint16): bool
               %{
               if ( ::dnp3_analog_input16_woTime )
                       {
                       BifEvent::generate_dnp3_analog_input16_woTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value);
                       }

               return true;
               %}
	function get_dnp3_analog_input32_wTime(flag: uint8, value: uint32, time48: const_bytestring): bool
               %{
               if ( ::dnp3_analog_input32_wTime )
                       {
                       BifEvent::generate_dnp3_analog_input32_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value, bytestring_to_val(time48) );
                       }

               return true;
               %}
	function get_dnp3_analog_input16_wTime(flag: uint8, value: uint16, time48: const_bytestring): bool
               %{
               if ( ::dnp3_analog_input16_wTime )
                       {
                       BifEvent::generate_dnp3_analog_input16_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value, bytestring_to_val(time48) );
                       }

               return true;
               %}
	function get_dnp3_analog_inputSP_woTime(flag: uint8, value: uint32): bool
               %{
               if ( ::dnp3_analog_inputSP_woTime )
                       {
                       BifEvent::generate_dnp3_analog_inputSP_woTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value );
                       }

               return true;
               %}
	function get_dnp3_analog_inputDP_woTime(flag: uint8, value_low: uint32, value_high: uint32): bool
               %{
               if ( ::dnp3_analog_inputDP_woTime )
                       {
                       BifEvent::generate_dnp3_analog_inputDP_woTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value_low, value_high );
                       }

               return true;
               %}
	function get_dnp3_analog_inputSP_wTime(flag: uint8, value: uint32, time48: const_bytestring): bool
               %{
               if ( ::dnp3_analog_inputSP_wTime )
                       {
                       BifEvent::generate_dnp3_analog_inputSP_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value, bytestring_to_val(time48) );
                       }

               return true;
               %}
	function get_dnp3_analog_inputDP_wTime(flag: uint8, value_low: uint32, value_high: uint32, time48: const_bytestring): bool
               %{
               if ( ::dnp3_analog_inputDP_wTime )
                       {
                       BifEvent::generate_dnp3_analog_inputDP_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value_low, value_high, bytestring_to_val(time48) );
                       }

               return true;
               %}
	function get_dnp3_analog_input32_wFlag(flag: uint8, value: uint32): bool
               %{
               if ( ::dnp3_analog_input32_wFlag )
                       {
                       BifEvent::generate_dnp3_analog_input32_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value);
                       }

               return true;
               %}
	function get_dnp3_analog_input16_wFlag(flag: uint8, value: uint16): bool
               %{
               if ( ::dnp3_analog_input16_wFlag )
                       {
                       BifEvent::generate_dnp3_analog_input16_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value);
                       }

               return true;
               %}
	function get_dnp3_analog_input32_woFlag(value: uint32): bool
               %{
               if ( ::dnp3_analog_input32_woFlag )
                       {
                       BifEvent::generate_dnp3_analog_input32_woFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), value);
                       }

               return true;
               %}
	function get_dnp3_analog_input16_woFlag(value: uint16): bool
               %{
               if ( ::dnp3_analog_input16_woFlag )
                       {
                       BifEvent::generate_dnp3_analog_input16_woFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), value);
                       }

               return true;
               %}
	function get_dnp3_analog_inputSP_wFlag(flag: uint8, value: uint32): bool
               %{
               if ( ::dnp3_analog_inputSP_wFlag )
                       {
                       BifEvent::generate_dnp3_analog_inputSP_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value);
                       }

               return true;
               %}
	function get_dnp3_analog_inputDP_wFlag(flag: uint8, value_low: uint32, value_high: uint32): bool
               %{
               if ( ::dnp3_analog_inputDP_wFlag )
                       {
                       BifEvent::generate_dnp3_analog_inputDP_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, value_low, value_high);
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
refine typeattr Dnp3_Application_Response_Header += &let {
       process_request: bool =  $context.flow.get_dnp3_application_response_header(application_control, function_code);
};

refine typeattr Object_Header += &let {
       process_request: bool =  $context.flow.get_dnp3_object_header(object_type_field, qualifier_field, number_of_item);
};
refine typeattr Data_Object += &let {
       process_request: bool =  $context.flow.get_dnp3_data_object(data_value);
};
refine typeattr AnalogInput32woTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input32_woTime(flag, value);
};
refine typeattr AnalogInput16woTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input16_woTime(flag, value);
};
refine typeattr AnalogInput32wTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input32_wTime(flag, value, time48);
};
refine typeattr AnalogInput16wTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input16_wTime(flag, value, time48);
};
refine typeattr AnalogInputSPwoTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputSP_woTime(flag, value);
};
refine typeattr AnalogInputDPwoTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputDP_woTime(flag, value_low, value_high);
};
refine typeattr AnalogInputSPwTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputSP_wTime(flag, value, time48);
};
refine typeattr AnalogInputDPwTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputDP_wTime(flag, value_low, value_high, time48);
};

refine typeattr AnalogInput16woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input16_woFlag(value);
};

refine typeattr Debug_Byte += &let {
       process_request: bool =  $context.flow.get_dnp3_debug_byte(debug);
};







