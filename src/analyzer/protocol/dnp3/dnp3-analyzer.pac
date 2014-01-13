
connection DNP3_Conn(bro_analyzer: BroAnalyzer) {
	upflow = DNP3_Flow(true);
	downflow = DNP3_Flow(false);
};

flow DNP3_Flow(is_orig: bool) {
	flowunit = DNP3_PDU(is_orig) withcontext (connection, this);

	function get_dnp3_header_block(start: uint16, len: uint16, ctrl: uint8, dest_addr: uint16, src_addr: uint16): bool
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

	function get_dnp3_application_request_header(fc: uint8): bool
		%{
		if ( ::dnp3_application_request_header )
			{
			BifEvent::generate_dnp3_application_request_header(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				fc
				);
			}
		return true;
		%}

	function get_dnp3_application_response_header(fc: uint8, iin: uint16): bool
		%{
		if ( ::dnp3_application_response_header )
			{
			BifEvent::generate_dnp3_application_response_header(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				fc,
				iin
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

	function get_dnp3_object_prefix(prefix_value: uint32): bool
		%{
		if ( ::dnp3_object_prefix )
			{
			BifEvent::generate_dnp3_object_prefix(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), prefix_value);
			}

		return true;
		%}

	function get_dnp3_request_data_object(data_value: uint32): bool
		%{
		if ( ::dnp3_request_data_object )
			{
			BifEvent::generate_dnp3_request_data_object(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), data_value);
			}

		return true;
		%}

	function get_dnp3_response_data_object(data_value: uint32): bool
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

	#g0
	function get_dnp3_attribute_common(data_type_code: uint8, leng: uint8, attribute_obj: const_bytestring): bool
		%{
		if ( ::dnp3_attribute_common )
			{
			BifEvent::generate_dnp3_attribute_common(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), data_type_code, leng, bytestring_to_val(attribute_obj) );
			}

		return true;
		%}

	#g2v2
	function get_dnp3_biewatime(flag: uint8, time48: const_bytestring): bool
		%{
		if ( ::dnp3_biewatime )
			{
			BifEvent::generate_dnp3_biewatime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, bytestring_to_val(time48) );
			}

		return true;
		%}


	#g2v3
	function get_dnp3_biewrtime(flag: uint8, time16: uint16): bool
		%{
		if ( ::dnp3_biewrtime )
			{
			BifEvent::generate_dnp3_biewrtime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, time16 );
			}

		return true;
		%}

	#g4v2
	function get_dnp3_doublein_eveatime(flag: uint8, time48: const_bytestring): bool
		%{
		if ( ::dnp3_doublein_eveatime )
			{
			BifEvent::generate_dnp3_doublein_eveatime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, bytestring_to_val(time48) );
			}

		return true;
		%}

	#g4v3
	function get_dnp3_doublein_evertime(flag: uint8, time16: uint16): bool
		%{
		if ( ::dnp3_doublein_evertime )
			{
			BifEvent::generate_dnp3_doublein_evertime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, time16 );
			}

		return true;
		%}

	#g11v2
	function get_dnp3_binout_eveatime(flag: uint8, time48: const_bytestring): bool
		%{
		if ( ::dnp3_binout_eveatime )
			{
			BifEvent::generate_dnp3_binout_eveatime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, bytestring_to_val(time48) );
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
				is_orig(), control_code, count8, on_time, off_time, status_code);
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
				is_orig(), control_code, count8, on_time, off_time, status_code);
			}

		return true;
		%}

	#g13v2
	function get_dnp3_binoutcmd_eveatime(flag: uint8, time48: const_bytestring): bool
		%{
		if ( ::dnp3_binoutcmd_eveatime )
			{
			BifEvent::generate_dnp3_binoutcmd_eveatime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, bytestring_to_val(time48));
			}

		return true;
		%}
	
	# g20v1
	function get_dnp3_counter_32wFlag(flag: uint8, count_value: uint32): bool
		%{
		if ( ::dnp3_counter_32wFlag )
			{
			BifEvent::generate_dnp3_counter_32wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value);
			}

		return true;
		%}

	# g20v2
	function get_dnp3_counter_16wFlag(flag: uint8, count_value: uint16): bool
		%{
		if ( ::dnp3_counter_16wFlag )
			{
			BifEvent::generate_dnp3_counter_16wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value);
			}

		return true;
		%}

	# g20v5
	function get_dnp3_counter_32woFlag(count_value: uint32): bool
		%{
		if ( ::dnp3_counter_32woFlag )
			{
			BifEvent::generate_dnp3_counter_32woFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), count_value);
			}

		return true;
		%}

	# g20v6
	function get_dnp3_counter_16woFlag(count_value: uint16): bool
		%{
		if ( ::dnp3_counter_16woFlag )
			{
			BifEvent::generate_dnp3_counter_16woFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), count_value);
			}

		return true;
		%}

	# g21v1
	function get_dnp3_frozen_counter_32wFlag(flag: uint8, count_value: uint32): bool
		%{
		if ( ::dnp3_frozen_counter_32wFlag )
			{
			BifEvent::generate_dnp3_frozen_counter_32wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value);
			}

		return true;
		%}

	# g21v2
	function get_dnp3_frozen_counter_16wFlag(flag: uint8, count_value: uint16): bool
		%{
		if ( ::dnp3_frozen_counter_16wFlag )
			{
			BifEvent::generate_dnp3_frozen_counter_16wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value);
			}

		return true;
		%}

	# g21v5
	function get_dnp3_frozen_counter_32wFlagTime(flag: uint8, count_value: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozen_counter_32wFlagTime )
			{
			BifEvent::generate_dnp3_frozen_counter_32wFlagTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g21v6
	function get_dnp3_frozen_counter_16wFlagTime(flag: uint8, count_value: uint16, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozen_counter_16wFlagTime )
			{
			BifEvent::generate_dnp3_frozen_counter_16wFlagTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g21v9
	function get_dnp3_frozen_counter_32woFlag(count_value: uint32): bool
		%{
		if ( ::dnp3_frozen_counter_32woFlag )
			{
			BifEvent::generate_dnp3_frozen_counter_32woFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), count_value);
			}

		return true;
		%}

	# g21v10
	function get_dnp3_frozen_counter_16woFlag(count_value: uint16): bool
		%{
		if ( ::dnp3_frozen_counter_16woFlag )
			{
			BifEvent::generate_dnp3_frozen_counter_16woFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), count_value);
			}

		return true;
		%}

	# g22v1
	function get_dnp3_counterEve_32wFlag(flag: uint8, count_value: uint32): bool
		%{
		if ( ::dnp3_counterEve_32wFlag )
			{
			BifEvent::generate_dnp3_counterEve_32wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value);
			}

		return true;
		%}

	# g22v2
	function get_dnp3_counterEve_16wFlag(flag: uint8, count_value: uint16): bool
		%{
		if ( ::dnp3_counterEve_16wFlag )
			{
			BifEvent::generate_dnp3_counterEve_16wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value);
			}

		return true;
		%}
	
	# g22v5
	function get_dnp3_counterEve_32wFlagTime(flag: uint8, count_value: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_counterEve_32wFlagTime )
			{
			BifEvent::generate_dnp3_counterEve_32wFlagTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g22v6
	function get_dnp3_counterEve_16wFlagTime(flag: uint8, count_value: uint16, time48: const_bytestring): bool
		%{
		if ( ::dnp3_counterEve_16wFlagTime )
			{
			BifEvent::generate_dnp3_counterEve_16wFlagTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g23v1
	function get_dnp3_frozenCounterEve_32wFlag(flag: uint8, count_value: uint32): bool
		%{
		if ( ::dnp3_frozenCounterEve_32wFlag )
			{
			BifEvent::generate_dnp3_frozenCounterEve_32wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value);
			}

		return true;
		%}

	# g23v2
	function get_dnp3_frozenCounterEve_16wFlag(flag: uint8, count_value: uint16): bool
		%{
		if ( ::dnp3_frozenCounterEve_16wFlag )
			{
			BifEvent::generate_dnp3_frozenCounterEve_16wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value);
			}

		return true;
		%}
	
	# g23v5
	function get_dnp3_frozenCounterEve_32wFlagTime(flag: uint8, count_value: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozenCounterEve_32wFlagTime )
			{
			BifEvent::generate_dnp3_frozenCounterEve_32wFlagTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g23v6
	function get_dnp3_frozenCounterEve_16wFlagTime(flag: uint8, count_value: uint16, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozenCounterEve_16wFlagTime )
			{
			BifEvent::generate_dnp3_frozenCounterEve_16wFlagTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, count_value, bytestring_to_val(time48));
			}

		return true;
		%}


	# g30v1
	function get_dnp3_analog_input_32wFlag(flag: uint8, value: int32): bool
		%{
		if ( ::dnp3_analog_input_32wFlag )
			{
			BifEvent::generate_dnp3_analog_input_32wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g30v2
	function get_dnp3_analog_input_16wFlag(flag: uint8, value: int16): bool
		%{
		if ( ::dnp3_analog_input_16wFlag )
			{
			BifEvent::generate_dnp3_analog_input_16wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g30v3
	function get_dnp3_analog_input_32woFlag(value: int32): bool
		%{
		if ( ::dnp3_analog_input_32woFlag )
			{
			BifEvent::generate_dnp3_analog_input_32woFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), value);
			}

		return true;
		%}

	#g30v4
	function get_dnp3_analog_input_16woFlag(value: int16): bool
		%{
		if ( ::dnp3_analog_input_16woFlag )
			{
			BifEvent::generate_dnp3_analog_input_16woFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), value);
			}

		return true;
		%}

	# g30v5
	function get_dnp3_analog_input_SPwFlag(flag: uint8, value: uint32): bool
		%{
		if ( ::dnp3_analog_input_SPwFlag )
			{
			BifEvent::generate_dnp3_analog_input_SPwFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g30v6
	function get_dnp3_analog_input_DPwFlag(flag: uint8, value_low: uint32, value_high: uint32): bool
		%{
		if ( ::dnp3_analog_input_DPwFlag )
			{
			BifEvent::generate_dnp3_analog_input_DPwFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value_low, value_high);
			}

		return true;
		%}

	# g31v1
	function get_dnp3_frozen_analog_input_32wFlag(flag: uint8, frozen_value: int32): bool
		%{
		if ( ::dnp3_frozen_analog_input_32wFlag )
			{
			BifEvent::generate_dnp3_frozen_analog_input_32wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value);
			}

		return true;
		%}

	# g31v2
	function get_dnp3_frozen_analog_input_16wFlag(flag: uint8, frozen_value: int16): bool
		%{
		if ( ::dnp3_frozen_analog_input_16wFlag )
			{
			BifEvent::generate_dnp3_frozen_analog_input_16wFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value);
			}

		return true;
		%}

	# g31v3
	function get_dnp3_frozen_analog_input_32wTime(flag: uint8, frozen_value: int32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozen_analog_input_32wTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_32wTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g31v4
	function get_dnp3_frozen_analog_input_16wTime(flag: uint8, frozen_value: int16, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozen_analog_input_16wTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_16wTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g31v5
	function get_dnp3_frozen_analog_input_32woFlag(frozen_value: int32): bool
		%{
		if ( ::dnp3_frozen_analog_input_32woFlag )
			{
			BifEvent::generate_dnp3_frozen_analog_input_32woFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), frozen_value);
			}

		return true;
		%}

	# g31v6
	function get_dnp3_frozen_analog_input_16woFlag(frozen_value: int16): bool
		%{
		if ( ::dnp3_frozen_analog_input_16woFlag )
			{
			BifEvent::generate_dnp3_frozen_analog_input_16woFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), frozen_value);
			}

		return true;
		%}

	# g31v7
	function get_dnp3_frozen_analog_input_SPwFlag(flag: uint8, frozen_value: uint32): bool
		%{
		if ( ::dnp3_frozen_analog_input_SPwFlag )
			{
			BifEvent::generate_dnp3_frozen_analog_input_SPwFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value);
			}

		return true;
		%}

	# g31v8
	function get_dnp3_frozen_analog_input_DPwFlag(flag: uint8, frozen_value_low: uint32, frozen_value_high: uint32): bool
		%{
		if ( ::dnp3_frozen_analog_input_DPwFlag )
			{
			BifEvent::generate_dnp3_frozen_analog_input_DPwFlag(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value_low, frozen_value_high);
			}

		return true;
		%}

	# g32v1
	function get_dnp3_analog_input_event_32woTime(flag: uint8, value: int32): bool
		%{
		if ( ::dnp3_analog_input_event_32woTime )
			{
			BifEvent::generate_dnp3_analog_input_event_32woTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g32v2
	function get_dnp3_analog_input_event_16woTime(flag: uint8, value: int16): bool
		%{
		if ( ::dnp3_analog_input_event_16woTime )
			{
			BifEvent::generate_dnp3_analog_input_event_16woTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g32v3
	function get_dnp3_analog_input_event_32wTime(flag: uint8, value: int32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_analog_input_event_32wTime )
			{
			BifEvent::generate_dnp3_analog_input_event_32wTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g32v4
	function get_dnp3_analog_input_event_16wTime(flag: uint8, value: int16, time48: const_bytestring): bool
		%{
		if ( ::dnp3_analog_input_event_16wTime )
			{
			BifEvent::generate_dnp3_analog_input_event_16wTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g32v5
	function get_dnp3_analog_input_event_SPwoTime(flag: uint8, value: uint32): bool
		%{
		if ( ::dnp3_analog_input_event_SPwoTime )
			{
			BifEvent::generate_dnp3_analog_input_event_SPwoTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g32v6
	function get_dnp3_analog_input_event_DPwoTime(flag: uint8, value_low: uint32, value_high: uint32): bool
		%{
		if ( ::dnp3_analog_input_event_DPwoTime )
			{
			BifEvent::generate_dnp3_analog_input_event_DPwoTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value_low, value_high);
			}

		return true;
		%}

	# g32v7
	function get_dnp3_analog_input_event_SPwTime(flag: uint8, value: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_analog_input_event_SPwTime )
			{
			BifEvent::generate_dnp3_analog_input_event_SPwTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g32v8
	function get_dnp3_analog_input_event_DPwTime(flag: uint8, value_low: uint32, value_high: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_analog_input_event_DPwTime )
			{
			BifEvent::generate_dnp3_analog_input_event_DPwTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value_low, value_high, bytestring_to_val(time48));
			}

		return true;
		%}

	# g33v1
	function get_dnp3_frozen_analog_input_event_32woTime(flag: uint8, frozen_value: int32): bool
		%{
		if ( ::dnp3_frozen_analog_input_event_32woTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_event_32woTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value);
			}

		return true;
		%}

	# g33v2
	function get_dnp3_frozen_analog_input_event_16woTime(flag: uint8, frozen_value: int16): bool
		%{
		if ( ::dnp3_frozen_analog_input_event_16woTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_event_16woTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value);
			}

		return true;
		%}

	# g33v3
	function get_dnp3_frozen_analog_input_event_32wTime(flag: uint8, frozen_value: int32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozen_analog_input_event_32wTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_event_32wTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g33v4
	function get_dnp3_frozen_analog_input_event_16wTime(flag: uint8, frozen_value: int16, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozen_analog_input_event_16wTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_event_16wTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g33v5
	function get_dnp3_frozen_analog_input_event_SPwoTime(flag: uint8, frozen_value: uint32): bool
		%{
		if ( ::dnp3_frozen_analog_input_event_SPwoTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_event_SPwoTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value);
			}

		return true;
		%}

	# g33v6
	function get_dnp3_frozen_analog_input_event_DPwoTime(flag: uint8, frozen_value_low: uint32, frozen_value_high: uint32): bool
		%{
		if ( ::dnp3_frozen_analog_input_event_DPwoTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_event_DPwoTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value_low, frozen_value_high);
			}

		return true;
		%}

	# g33v7
	function get_dnp3_frozen_analog_input_event_SPwTime(flag: uint8, frozen_value: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozen_analog_input_event_SPwTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_event_SPwTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g33v8
	function get_dnp3_frozen_analog_input_event_DPwTime(flag: uint8, frozen_value_low: uint32, frozen_value_high: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_frozen_analog_input_event_DPwTime )
			{
			BifEvent::generate_dnp3_frozen_analog_input_event_DPwTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, frozen_value_low, frozen_value_high, bytestring_to_val(time48));
			}

		return true;
		%}

	# g40v1
	function get_dnp3_analog_output_status32(flag: uint8, status: uint32): bool
		%{
		if ( ::dnp3_analog_output_status32 )
			{
			BifEvent::generate_dnp3_analog_output_status32(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, status);
			}

		return true;
		%}

	# g40v2
	function get_dnp3_analog_output_status16(flag: uint8, status: uint16): bool
		%{
		if ( ::dnp3_analog_output_status16 )
			{
			BifEvent::generate_dnp3_analog_output_status16(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, status);
			}

		return true;
		%}
	
	# g40v3
	function get_dnp3_analog_output_statusSP(flag: uint8, status: uint32): bool
		%{
		if ( ::dnp3_analog_output_statusSP )
			{
			BifEvent::generate_dnp3_analog_output_statusSP(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, status);
			}

		return true;
		%}

	# g40v4
	function get_dnp3_analog_output_statusDP(flag: uint8, status_low: uint32, status_high: uint32): bool
		%{
		if ( ::dnp3_analog_output_statusDP )
			{
			BifEvent::generate_dnp3_analog_output_statusDP(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, status_low, status_high);
			}

		return true;
		%}
	# g41v1
	function get_dnp3_analog_output32(value: int32, con_status: uint8): bool
		%{
		if ( ::dnp3_analog_output32 )
			{
			BifEvent::generate_dnp3_analog_output32(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), value, con_status);
			}

		return true;
		%}

	# g41v2
	function get_dnp3_analog_output16(value: int16, con_status: uint8): bool
		%{
		if ( ::dnp3_analog_output16 )
			{
			BifEvent::generate_dnp3_analog_output16(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), value, con_status);
			}

		return true;
		%}
	
	# g41v3
	function get_dnp3_analog_outputSP(value: uint32, con_status: uint8): bool
		%{
		if ( ::dnp3_analog_outputSP )
			{
			BifEvent::generate_dnp3_analog_outputSP(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), value, con_status);
			}

		return true;
		%}

	# g41v4
	function get_dnp3_analog_outputDP(value_low: uint32, value_high: uint32 ,  con_status: uint8): bool
		%{
		if ( ::dnp3_analog_outputDP )
			{
			BifEvent::generate_dnp3_analog_outputDP(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), value_high, value_high, con_status);
			}

		return true;
		%}
	
	# g42v1
	function get_dnp3_analog_output_event_32woTime(flag: uint8, value: int32): bool
		%{
		if ( ::dnp3_analog_output_event_32woTime )
			{
			BifEvent::generate_dnp3_analog_output_event_32woTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g42v2
	function get_dnp3_analog_output_event_16woTime(flag: uint8, value: int16): bool
		%{
		if ( ::dnp3_analog_output_event_16woTime )
			{
			BifEvent::generate_dnp3_analog_output_event_16woTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g42v3
	function get_dnp3_analog_output_event_32wTime(flag: uint8, value: int32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_analog_output_event_32wTime )
			{
			BifEvent::generate_dnp3_analog_output_event_32wTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value, bytestring_to_val(time48));
			}

		return true;
		%}
	
	# g42v4
	function get_dnp3_analog_output_event_16wTime(flag: uint8, value: int16, time48: const_bytestring): bool
		%{
		if ( ::dnp3_analog_output_event_16wTime )
			{
			BifEvent::generate_dnp3_analog_output_event_16wTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g42v5
	function get_dnp3_analog_output_event_SPwoTime(flag: uint8, value: uint32): bool
		%{
		if ( ::dnp3_analog_output_event_SPwoTime )
			{
			BifEvent::generate_dnp3_analog_output_event_SPwoTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value);
			}

		return true;
		%}

	# g42v6
	function get_dnp3_analog_output_event_DPwoTime(flag: uint8, value_low: uint32, value_high: uint32): bool
		%{
		if ( ::dnp3_analog_output_event_DPwoTime )
			{
			BifEvent::generate_dnp3_analog_output_event_DPwoTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value_low, value_high);
			}

		return true;
		%}

	# g42v7
	function get_dnp3_analog_output_event_SPwTime(flag: uint8, value: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_analog_output_event_SPwTime )
			{
			BifEvent::generate_dnp3_analog_output_event_SPwTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value, bytestring_to_val(time48));
			}

		return true;
		%}

	# g42v8
	function get_dnp3_analog_output_event_DPwTime(flag: uint8, value_low: uint32, value_high: uint32, time48: const_bytestring): bool
		%{
		if ( ::dnp3_analog_output_event_DPwTime )
			{
			BifEvent::generate_dnp3_analog_output_event_DPwTime(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), flag, value_low, value_high, bytestring_to_val(time48));
			}

		return true;
		%}

	# g50v1
	function get_dnp3_abs_time(time48: const_bytestring): bool
		%{
		if ( ::dnp3_abs_time )
			{
			BifEvent::generate_dnp3_abs_time(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), bytestring_to_val(time48));
			}

		return true;
		%}

	# g50v2
	function get_dnp3_abs_time_interval(time48: const_bytestring, interval32: uint32): bool
		%{
		if ( ::dnp3_abs_time_interval )
			{
			BifEvent::generate_dnp3_abs_time_interval(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), bytestring_to_val(time48), interval32);
			}

		return true;
		%}

	# g50v1
	function get_dnp3_last_abs_time(time48: const_bytestring): bool
		%{
		if ( ::dnp3_last_abs_time )
			{
			BifEvent::generate_dnp3_last_abs_time(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), bytestring_to_val(time48));
			}

		return true;
		%}

	# g70v1
	function get_dnp3_record_obj(record_size: uint16, record_oct: const_bytestring): bool
		%{
		if ( ::dnp3_record_obj )
			{
			BifEvent::generate_dnp3_record_obj(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), record_size, bytestring_to_val(record_oct));
			}

		return true;
		%}

	function get_dnp3_file_control_id(name_size: uint16, type_code: uint8, attr_code: uint8,
					start_rec: uint16, end_rec: uint16, file_size: uint32,
					time_create: const_bytestring, permission: uint16,
					file_id: uint16, owner_id: uint32, group_id: uint32,
					function_code: uint8, status_code: uint8, file_name: bytestring): bool
		%{
		if ( ::dnp3_file_control_id )
			{
			BifEvent::generate_dnp3_file_control_id(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), name_size, type_code, attr_code, start_rec, end_rec, file_size, 
				bytestring_to_val(time_create), permission, file_id, owner_id, group_id, function_code,
				status_code, bytestring_to_val(file_name));
			}

		return true;
		%}

	# g70v5
	function get_dnp3_file_transport(file_handle: uint32, block_num: uint32, file_data: const_bytestring): bool
		%{
		if ( ::dnp3_file_transport )
			{
			BifEvent::generate_dnp3_file_transport(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), file_handle, block_num, bytestring_to_val(file_data));
			}

		return true;
		%}

#### for debug use or unknown data types used in "case"
	function get_dnp3_debug_byte(debug: const_bytestring): bool
		%{
		if ( ::dnp3_debug_byte )
			{
			BifEvent::generate_dnp3_debug_byte (
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), bytestring_to_val(debug));
			}

		return true;
		%}

};

refine typeattr Header_Block += &let {
	get_header: bool =  $context.flow.get_dnp3_header_block(start, len, ctrl, dest_addr, src_addr);
};

refine typeattr DNP3_Application_Request_Header += &let {
	process_request: bool =  $context.flow.get_dnp3_application_request_header(function_code);
};

refine typeattr DNP3_Application_Response_Header += &let {
	process_request: bool =  $context.flow.get_dnp3_application_response_header(function_code, internal_indications);
};

refine typeattr Object_Header += &let {
	process_request: bool =  $context.flow.get_dnp3_object_header(object_type_field, qualifier_field, number_of_item, rf_value_low, rf_value_high);
};

refine typeattr Prefix_Type += &let {
	prefix_called: bool =  $context.flow.get_dnp3_object_prefix(prefix_value);
};

refine typeattr Request_Data_Object += &let {
	process_request: bool =  $context.flow.get_dnp3_request_data_object(data_value);
};

refine typeattr Response_Data_Object += &let {
	process_request: bool =  $context.flow.get_dnp3_response_data_object(data_value);
};

# g0
refine typeattr AttributeCommon += &let {
	process_request: bool =  $context.flow.get_dnp3_attribute_common(data_type_code, leng, attribute_obj);
};

# g2v2
refine typeattr BinInEveAtime += &let {
	process_request: bool =  $context.flow.get_dnp3_biewatime(flag, time48);
};

# g2v3
refine typeattr BinInEveRtime += &let {
	process_request: bool =  $context.flow.get_dnp3_biewrtime(flag, time16);
};

# g4v2
refine typeattr DoubleInEveAtime += &let {
	process_request: bool =  $context.flow.get_dnp3_doublein_eveatime(flag, time48);
};

# g4v3
refine typeattr DoubleInEveRtime += &let {
	process_request: bool =  $context.flow.get_dnp3_doublein_evertime(flag, time16);
};

# g11v2
refine typeattr BinOutEveAtime += &let {
	process_request: bool =  $context.flow.get_dnp3_binout_eveatime(flag, time48);
};

# g12v1
refine typeattr CROB += &let {
	process_request: bool =  $context.flow.get_dnp3_crob(control_code, count, on_time, off_time, status_code);
};

# g12v2
refine typeattr PCB += &let {
	process_request: bool =  $context.flow.get_dnp3_pcb(control_code, count, on_time, off_time, status_code);
};

# g13v2
refine typeattr BinOutCmdEveAtime += &let {
	process_request: bool =  $context.flow.get_dnp3_binoutcmd_eveatime(flag, time48);
};


# g20v1
refine typeattr Counter32wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_counter_32wFlag(flag, count_value);
};

# g20v2
refine typeattr Counter16wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_counter_16wFlag(flag, count_value);
};

# g20v5
refine typeattr Counter32woFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_counter_32woFlag(count_value);
};

# g20v6
refine typeattr Counter16woFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_counter_16woFlag(count_value);
};

# g21v1
refine typeattr FrozenCounter32wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_counter_32wFlag(flag, count_value);
};

# g21v2
refine typeattr FrozenCounter16wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_counter_16wFlag(flag, count_value);
};
# g21v5
refine typeattr FrozenCounter32wFlagTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_counter_32wFlagTime(flag, count_value, time48);
};

# g21v6
refine typeattr FrozenCounter16wFlagTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_counter_16wFlagTime(flag, count_value, time48);
};

# g21v9
refine typeattr FrozenCounter32woFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_counter_32woFlag(count_value);
};

# g21v10
refine typeattr FrozenCounter16woFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_counter_16woFlag(count_value);
};

# g22v1
refine typeattr CounterEve32wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_counterEve_32wFlag(flag, count_value);
};

# g22v2
refine typeattr CounterEve16wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_counterEve_16wFlag(flag, count_value);
};

# g22v5
refine typeattr CounterEve32wFlagTime += &let {
	process_request: bool =  $context.flow.get_dnp3_counterEve_32wFlagTime(flag, count_value, time48);
};

# g22v6
refine typeattr CounterEve16wFlagTime += &let {
	process_request: bool =  $context.flow.get_dnp3_counterEve_16wFlagTime(flag, count_value, time48);
};

# g23v1
refine typeattr FrozenCounterEve32wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozenCounterEve_32wFlag(flag, count_value);
};

# g23v2
refine typeattr FrozenCounterEve16wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozenCounterEve_16wFlag(flag, count_value);
};

# g23v5
refine typeattr FrozenCounterEve32wFlagTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozenCounterEve_32wFlagTime(flag, count_value, time48);
};

# g23v6
refine typeattr FrozenCounterEve16wFlagTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozenCounterEve_16wFlagTime(flag, count_value, time48);
};

# g30v1
refine typeattr AnalogInput32wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_32wFlag(flag, value);
};

# g30v2
refine typeattr AnalogInput16wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_16wFlag(flag, value);
};

# g30v3
refine typeattr AnalogInput32woFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_32woFlag(value);
};

# g30v4
refine typeattr AnalogInput16woFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_16woFlag(value);
};

# g30v5
refine typeattr AnalogInputSPwFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_SPwFlag(flag, value);
};

# g30v6
refine typeattr AnalogInputDPwFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_DPwFlag(flag, value_low, value_high);
};

# g31v1
refine typeattr FrozenAnalogInput32wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_32wFlag(flag, frozen_value);
};

# g31v2
refine typeattr FrozenAnalogInput16wFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_16wFlag(flag, frozen_value);
};

# g31v3
refine typeattr FrozenAnalogInput32wTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_32wTime(flag, frozen_value, time48);
};

# g31v4
refine typeattr FrozenAnalogInput16wTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_16wTime(flag, frozen_value, time48);
};

# g31v5
refine typeattr FrozenAnalogInput32woFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_32woFlag(frozen_value);
};

# g31v6
refine typeattr FrozenAnalogInput16woFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_16woFlag(frozen_value);
};

# g31v7
refine typeattr FrozenAnalogInputSPwFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_SPwFlag(flag, frozen_value);
};

# g31v8
refine typeattr FrozenAnalogInputDPwFlag += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_DPwFlag(flag, frozen_value_low, frozen_value_high);
};

# g32v1
refine typeattr AnalogInput32woTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_event_32woTime(flag, value);
};

# g32v2
refine typeattr AnalogInput16woTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_event_16woTime(flag, value);
};

# g32v3
refine typeattr AnalogInput32wTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_event_32wTime(flag, value, time48);
};

# g32v4
refine typeattr AnalogInput16wTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_event_16wTime(flag, value, time48);
};

# g32v5
refine typeattr AnalogInputSPwoTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_event_SPwoTime(flag, value);
};

# g32v6
refine typeattr AnalogInputDPwoTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_event_DPwoTime(flag, value_low, value_high);
};

# g32v7
refine typeattr AnalogInputSPwTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_event_SPwTime(flag, value, time48);
};

# g32v8
refine typeattr AnalogInputDPwTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_input_event_DPwTime(flag, value_low, value_high, time48);
};

# g33v1
refine typeattr FrozenAnaInputEve32woTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_event_32woTime(flag, f_value);
};

# g33v2
refine typeattr FrozenAnaInputEve16woTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_event_16woTime(flag, f_value);
};

# g33v3
refine typeattr FrozenAnaInputEve32wTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_event_32wTime(flag, f_value, time48);
};

# g33v4
refine typeattr FrozenAnaInputEve16wTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_event_16wTime(flag, f_value, time48);
};

# g33v5
refine typeattr FrozenAnaInputEveSPwoTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_event_SPwoTime(flag, f_value);
};

# g33v6
refine typeattr FrozenAnaInputEveDPwoTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_event_DPwoTime(flag, f_value_low, f_value_high);
};

# g33v7
refine typeattr FrozenAnaInputEveSPwTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_event_SPwTime(flag, f_value, time48);
};

# g33v8
refine typeattr FrozenAnaInputEveDPwTime += &let {
	process_request: bool =  $context.flow.get_dnp3_frozen_analog_input_event_DPwTime(flag, f_value_low, f_value_high, time48);
};

# g40v1
refine typeattr AnaOutStatus32 += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_status32(flag, status);
};

# g40v2
refine typeattr AnaOutStatus16 += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_status16(flag, status);
};

# g40v3
refine typeattr AnaOutStatusSP += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_statusSP(flag, status);
};

# g40v4
refine typeattr AnaOutStatusDP += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_statusDP(flag, status_low, status_high);
};

# g41v1
refine typeattr AnaOut32 += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output32(value, con_status);
};

# g41v2
refine typeattr AnaOut16 += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output16(value, con_status);
};

# g41v3
refine typeattr AnaOutSP += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_outputSP(value, con_status);
};

# g41v4
refine typeattr AnaOutDP += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_outputDP(value_low, value_high, con_status);
};

# g42v1
refine typeattr AnaOutEve32woTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_event_32woTime(flag, value);
};

# g42v2
refine typeattr AnaOutEve16woTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_event_16woTime(flag, value);
};

# g42v3
refine typeattr AnaOutEve32wTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_event_32wTime(flag, value, time48);
};

# g42v4
refine typeattr AnaOutEve16wTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_event_16wTime(flag, value, time48);
};

# g42v5
refine typeattr AnaOutEveSPwoTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_event_SPwoTime(flag, value);
};

# g42v6
refine typeattr AnaOutEveDPwoTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_event_DPwoTime(flag, value_low, value_high);
};

# g42v7
refine typeattr AnaOutEveSPwTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_event_SPwTime(flag, value, time48);
};

# g42v8
refine typeattr AnaOutEveDPwTime += &let {
	process_request: bool =  $context.flow.get_dnp3_analog_output_event_DPwTime(flag, value_low, value_high, time48);
};

# g50v1
refine typeattr AbsTime += &let {
	process_request: bool =  $context.flow.get_dnp3_abs_time(time48);
};

# g50v2
refine typeattr AbsTimeInterval += &let {
	process_request: bool =  $context.flow.get_dnp3_abs_time_interval(time48 , interval32);
};

# g50v3
refine typeattr Last_AbsTime += &let {
	process_request: bool =  $context.flow.get_dnp3_last_abs_time(time48);
};

# g70v1
refine typeattr Record_Obj += &let {
        result: bool =  $context.flow.get_dnp3_record_obj(record_size, record_oct);
};

refine typeattr File_Control_ID += &let {
        result: bool =  $context.flow.get_dnp3_file_control_id(name_size, type_code, attr_code, start_rec, end_rec, file_size,
                                time_create, permission, file_id, owner_id, group_id, function_code, status_code, file_name);
};

# g70v5
refine typeattr File_Transport += &let {
        result: bool =  $context.flow.get_dnp3_file_transport(file_handle, block_num, file_data);
};

refine typeattr Debug_Byte += &let {
	process_request: bool =  $context.flow.get_dnp3_debug_byte(debug);
};

