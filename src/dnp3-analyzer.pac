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
       function get_dnp3_object_header(obj_type: uint16, qua_field: uint8, number: uint32, rf_low: uint32, rf_high: uint32 ): bool
               %{
               if ( ::dnp3_object_header )
                       {
                       BifEvent::generate_dnp3_object_header(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), obj_type, qua_field, number, rf_low, rf_high);
                       }

               return true;
               %}
	function get_dnp3_response_data_object(data_value: uint8): bool
               %{
               if ( ::dnp3_response_data_object )
                       {
                       BifEvent::generate_dnp3_response_data_object(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), data_value);
                       }

               return true;
               %}
	#g12v1
	function get_dnp3_crob(control_code: uint8, count8: uint8, on_time: uint32, off_time: uint32, status_code: uint8): bool
               %{
               if ( ::dnp3_crob )
                       {
                       BifEvent::generate_dnp3_crob(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), control_code, count8, on_time, off_time, status_code );
                       }

               return true;
               %}
	#g12v2
	function get_dnp3_pcb(control_code: uint8, count8: uint8, on_time: uint32, off_time: uint32, status_code: uint8): bool
               %{
               if ( ::dnp3_pcb )
                       {
                       BifEvent::generate_dnp3_pcb(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), control_code, count8, on_time, off_time, status_code );
                       }

               return true;
               %}
	# g20v1
	function get_dnp3_counter32_wFlag(flag: uint8, count_value: uint32): bool
               %{
               if ( ::dnp3_counter32_wFlag )
                       {
                       BifEvent::generate_dnp3_counter32_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, count_value );
                       }

               return true;
               %}
	# g20v2
	function get_dnp3_counter16_wFlag(flag: uint8, count_value: uint16): bool
               %{
               if ( ::dnp3_counter16_wFlag )
                       {
                       BifEvent::generate_dnp3_counter16_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, count_value );
                       }

               return true;
               %}
	# g20v5
	function get_dnp3_counter32_woFlag(count_value: uint32): bool
               %{
               if ( ::dnp3_counter32_woFlag )
                       {
                       BifEvent::generate_dnp3_counter32_woFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), count_value );
                       }

               return true;
               %}
	# g20v6
	function get_dnp3_counter16_woFlag(count_value: uint16): bool
               %{
               if ( ::dnp3_counter16_woFlag )
                       {
                       BifEvent::generate_dnp3_counter16_woFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), count_value );
                       }

               return true;
               %}
	# g21v1
	function get_dnp3_frozen_counter32_wFlag(flag: uint8, count_value: uint32): bool
               %{
               if ( ::dnp3_frozen_counter32_wFlag )
                       {
                       BifEvent::generate_dnp3_frozen_counter32_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, count_value );
                       }

               return true;
               %}
	# g21v2
	function get_dnp3_frozen_counter16_wFlag(flag: uint8, count_value: uint16): bool
               %{
               if ( ::dnp3_frozen_counter16_wFlag )
                       {
                       BifEvent::generate_dnp3_frozen_counter16_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, count_value );
                       }

               return true;
               %}
	# g21v5
	function get_dnp3_frozen_counter32_wFlagTime(flag: uint8, count_value: uint32, time48: const_bytestring): bool
               %{
               if ( ::dnp3_frozen_counter32_wFlagTime )
                       {
                       BifEvent::generate_dnp3_frozen_counter32_wFlagTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, count_value, bytestring_to_val(time48) );
                       }

               return true;
               %}
	# g21v6
	function get_dnp3_frozen_counter16_wFlagTime(flag: uint8, count_value: uint16, time48: const_bytestring): bool
               %{
               if ( ::dnp3_frozen_counter16_wFlagTime )
                       {
                       BifEvent::generate_dnp3_frozen_counter16_wFlagTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, count_value, bytestring_to_val(time48) );
                       }

               return true;
               %}
	# g21v9
	function get_dnp3_frozen_counter32_woFlag(count_value: uint32): bool
               %{
               if ( ::dnp3_frozen_counter32_woFlag )
                       {
                       BifEvent::generate_dnp3_frozen_counter32_woFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), count_value );
                       }

               return true;
               %}
	# g21v10
	function get_dnp3_frozen_counter16_woFlag(count_value: uint16): bool
               %{
               if ( ::dnp3_frozen_counter16_woFlag )
                       {
                       BifEvent::generate_dnp3_frozen_counter16_woFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), count_value );
                       }

               return true;
               %}
	# g30v1
	function get_dnp3_analog_input32_wFlag(flag: uint8, value: int32): bool
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
	# g30v2
	function get_dnp3_analog_input16_wFlag(flag: uint8, value: int16): bool
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
	# g30v3
	function get_dnp3_analog_input32_woFlag(value: int32): bool
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
	#g30v4
	function get_dnp3_analog_input16_woFlag(value: int16): bool
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
	# g30v5
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
	# g30v6
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
	# g31v1
	function get_dnp3_frozen_analog_input32_wFlag(flag: uint8, frozen_value: int32): bool
               %{
               if ( ::dnp3_frozen_analog_input32_wFlag )
                       {
                       BifEvent::generate_dnp3_frozen_analog_input32_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value);
                       }

               return true;
               %}
	# g31v2
	function get_dnp3_frozen_analog_input16_wFlag(flag: uint8, frozen_value: int16): bool
               %{
               if ( ::dnp3_frozen_analog_input16_wFlag )
                       {
                       BifEvent::generate_dnp3_frozen_analog_input16_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value);
                       }

               return true;
               %}
	# g31v3
	function get_dnp3_frozen_analog_input32_wTime(flag: uint8, frozen_value: int32, time48: const_bytestring): bool
               %{
               if ( ::dnp3_frozen_analog_input32_wTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_input32_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value, bytestring_to_val(time48) );
                       }

               return true;
               %}
	# g31v4
	function get_dnp3_frozen_analog_input16_wTime(flag: uint8, frozen_value: int16, time48: const_bytestring): bool
               %{
               if ( ::dnp3_frozen_analog_input16_wTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_input16_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value, bytestring_to_val(time48) );
                       }

               return true;
               %}
	# g31v5
	function get_dnp3_frozen_analog_input32_woFlag(frozen_value: int32): bool
               %{
               if ( ::dnp3_frozen_analog_input32_woFlag )
                       {
                       BifEvent::generate_dnp3_frozen_analog_input32_woFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), frozen_value);
                       }

               return true;
               %}
	# g31v6
	function get_dnp3_frozen_analog_input16_woFlag(frozen_value: int16): bool
               %{
               if ( ::dnp3_frozen_analog_input16_woFlag )
                       {
                       BifEvent::generate_dnp3_frozen_analog_input16_woFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), frozen_value);
                       }

               return true;
               %}
	# g31v7
	function get_dnp3_frozen_analog_inputSP_wFlag(flag: uint8, frozen_value: uint32): bool
               %{
               if ( ::dnp3_frozen_analog_inputSP_wFlag )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputSP_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value);
                       }

               return true;
               %}
	# g31v8
	function get_dnp3_frozen_analog_inputDP_wFlag(flag: uint8, frozen_value_low: uint32, frozen_value_high: uint32): bool
               %{
               if ( ::dnp3_frozen_analog_inputDP_wFlag )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputDP_wFlag(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value_low, frozen_value_high );
                       }

               return true;
               %}

	# g32v1
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
	# g32v2
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
	# g32v3
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
	# g32v4
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
	# g32v5
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
	# g32v6
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
	# g32v7
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
	# g32v8
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

	# g 33 v 1 
        function get_dnp3_frozen_analog_inputevent32_woTime(flag: uint8, frozen_value: int32): bool
               %{
               if ( ::dnp3_frozen_analog_inputevent32_woTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputevent32_woTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value);
                       }

               return true;
               %}
	# g 33 v 2 
        function get_dnp3_frozen_analog_inputevent16_woTime(flag: uint8, frozen_value: int16): bool
               %{
               if ( ::dnp3_frozen_analog_inputevent16_woTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputevent16_woTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value);
                       }

               return true;
               %}
	
	# g 33 v 3
        function get_dnp3_frozen_analog_inputevent32_wTime(flag: uint8, frozen_value: int32, time48: const_bytestring): bool
               %{
               if ( ::dnp3_frozen_analog_inputevent32_wTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputevent32_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value, bytestring_to_val(time48) );
                       }

               return true;
               %}
	# g 33 v 4 
        function get_dnp3_frozen_analog_inputevent16_wTime(flag: uint8, frozen_value: int16, time48: const_bytestring): bool
               %{
               if ( ::dnp3_frozen_analog_inputevent16_wTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputevent16_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value, bytestring_to_val(time48));
                       }

               return true;
               %}
	# g 33 v 5 
        function get_dnp3_frozen_analog_inputeventSP_woTime(flag: uint8, frozen_value: uint32): bool
               %{
               if ( ::dnp3_frozen_analog_inputeventSP_woTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputeventSP_woTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value);
                       }

               return true;
               %}
	# g 33 v 6 
        function get_dnp3_frozen_analog_inputeventDP_woTime(flag: uint8, frozen_value_low: uint32, frozen_value_high: uint32): bool
               %{
               if ( ::dnp3_frozen_analog_inputeventDP_woTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputeventDP_woTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value_low, frozen_value_high);
                       }

               return true;
               %}
	# g 33 v 7 
        function get_dnp3_frozen_analog_inputeventSP_wTime(flag: uint8, frozen_value: uint32, time48: const_bytestring): bool
               %{
               if ( ::dnp3_frozen_analog_inputeventSP_wTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputeventSP_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value, bytestring_to_val(time48));
                       }

               return true;
               %}
	# g 33 v 8 
        function get_dnp3_frozen_analog_inputeventDP_wTime(flag: uint8, frozen_value_low: uint32, frozen_value_high: uint32, time48: const_bytestring): bool
               %{
               if ( ::dnp3_frozen_analog_inputeventDP_wTime )
                       {
                       BifEvent::generate_dnp3_frozen_analog_inputeventDP_wTime(
                               connection()->bro_analyzer(),
                               connection()->bro_analyzer()->Conn(),
                               is_orig(), flag, frozen_value_low, frozen_value_high, bytestring_to_val(time48));
                       }

               return true;
               %}

#### for debug use
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
       process_request: bool =  $context.flow.get_dnp3_object_header(object_type_field, qualifier_field, number_of_item, rf_value_low, rf_value_high);
};
refine typeattr Response_Data_Object += &let {
       process_request: bool =  $context.flow.get_dnp3_response_data_object(data_value);
};
# g12v1
refine typeattr CROB += &let {
       process_request: bool =  $context.flow.get_dnp3_crob(control_code, count, on_time, off_time, status_code);
};
# g12v2
refine typeattr PCB += &let {
       process_request: bool =  $context.flow.get_dnp3_pcb(control_code, count, on_time, off_time, status_code);
};
# g20v1
refine typeattr Counter32wFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_counter32_wFlag(flag, count_value);
};
# g20v2
refine typeattr Counter16wFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_counter16_wFlag(flag, count_value);
};
# g20v5
refine typeattr Counter32woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_counter32_woFlag(count_value);
};
# g20v6
refine typeattr Counter16woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_counter16_woFlag(count_value);
};
# g21v1
refine typeattr FrozenCounter32wFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_counter32_wFlag(flag, count_value);
};
# g21v2
refine typeattr FrozenCounter16wFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_counter16_wFlag(flag, count_value);
};
# g21v5
refine typeattr FrozenCounter32wFlagTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_counter32_wFlagTime(flag, count_value, time48);
};
# g21v6
refine typeattr FrozenCounter16wFlagTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_counter16_wFlagTime(flag, count_value, time48);
};
# g21v9
refine typeattr FrozenCounter32woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_counter32_woFlag(count_value);
};
# g21v10
refine typeattr FrozenCounter16woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_counter16_woFlag(count_value);
};
# g30v1
refine typeattr AnalogInput32wFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input32_wFlag(flag, value);
};
# g30v2
refine typeattr AnalogInput16wFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input16_wFlag(flag, value);
};
# g30v3
refine typeattr AnalogInput32woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input32_woFlag(value);
};
# g30v4
refine typeattr AnalogInput16woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input16_woFlag(value);
};
# g30v5
refine typeattr AnalogInputSPwFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputSP_wFlag(flag, value);
};
# g30v6
refine typeattr AnalogInputDPwFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputDP_wFlag(flag, value_low, value_high);
};
# g31v1
refine typeattr FrozenAnalogInput32wFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_input32_wFlag(flag, frozen_value);
};
# g31v2
refine typeattr FrozenAnalogInput16wFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_input16_wFlag(flag, frozen_value);
};
# g31v3
refine typeattr FrozenAnalogInput32wTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_input32_wTime(flag, frozen_value, time48);
};
# g31v4
refine typeattr FrozenAnalogInput16wTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_input16_wTime(flag, frozen_value, time48);
};
# g31v5
refine typeattr FrozenAnalogInput32woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_input32_woFlag(frozen_value);
};
# g31v6
refine typeattr FrozenAnalogInput16woFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_input16_woFlag(frozen_value);
};
# g31v7
refine typeattr FrozenAnalogInputSPwFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputSP_wFlag(flag, frozen_value);
};
# g31v8
refine typeattr FrozenAnalogInputDPwFlag += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputDP_wFlag(flag, frozen_value_low, frozen_value_high);
};
# g 32 v 1
refine typeattr AnalogInput32woTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input32_woTime(flag, value);
};
# g 32 v 2
refine typeattr AnalogInput16woTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input16_woTime(flag, value);
};
# g 32 v 3
refine typeattr AnalogInput32wTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input32_wTime(flag, value, time48);
};
# g 32 v 4
refine typeattr AnalogInput16wTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_input16_wTime(flag, value, time48);
};
# g 32 v 5
refine typeattr AnalogInputSPwoTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputSP_woTime(flag, value);
};
# g 32 v 6
refine typeattr AnalogInputDPwoTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputDP_woTime(flag, value_low, value_high);
};
# g 32 v 7
refine typeattr AnalogInputSPwTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputSP_wTime(flag, value, time48);
};
# g 32 v 8
refine typeattr AnalogInputDPwTime += &let {
       process_request: bool =  $context.flow.get_dnp3_analog_inputDP_wTime(flag, value_low, value_high, time48);
};
# g 33 v 1
refine typeattr FrozenAnaInputEve32woTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputevent32_woTime(flag, f_value);
};
# g 33 v 2
refine typeattr FrozenAnaInputEve16woTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputevent16_woTime(flag, f_value);
};
# g 33 v 3
refine typeattr FrozenAnaInputEve32wTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputevent32_wTime(flag, f_value, time48);
};
# g 33 v 4
refine typeattr FrozenAnaInputEve16wTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputevent16_wTime(flag, f_value, time48);
};
# g 33 v 5
refine typeattr FrozenAnaInputEveSPwoTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputeventSP_woTime(flag, f_value);
};
# g 33 v 6
refine typeattr FrozenAnaInputEveDPwoTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputeventDP_woTime(flag, f_value_low, f_value_high);
};
# g 33 v 7
refine typeattr FrozenAnaInputEveSPwTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputeventSP_wTime(flag, f_value, time48);
};
# g 33 v 8
refine typeattr FrozenAnaInputEveDPwTime += &let {
       process_request: bool =  $context.flow.get_dnp3_frozen_analog_inputeventDP_wTime(flag, f_value_low, f_value_high, time48);
};

refine typeattr Debug_Byte += &let {
       process_request: bool =  $context.flow.get_dnp3_debug_byte(debug);
};







