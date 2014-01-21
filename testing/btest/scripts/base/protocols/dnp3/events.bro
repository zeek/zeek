#
# @TEST-EXEC: bro -r $TRACES/dnp3/dnp3.trace %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat output | awk '{print $1}' | sort | uniq | wc -l >covered
# @TEST-EXEC: cat ${DIST}/src/analyzer/protocol/dnp3/events.bif  | grep "^event dnp3_" | wc -l >total
# @TEST-EXEC: echo `cat covered` of `cat total` events triggered by trace >coverage
# @TEST-EXEC: btest-diff coverage
# @TEST-EXEC: btest-diff dnp3.log
#
event dnp3_application_request_header(c: connection, is_orig: bool, fc: count)
	{
	print "dnp3_application_request_header", is_orig, fc;
	}

event dnp3_application_response_header(c: connection, is_orig: bool, fc: count, iin: count)
	{
	print "dnp3_application_response_header", is_orig, fc, iin;
	}

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	print "dnp3_object_header", is_orig, obj_type, qua_field, number, rf_low, rf_high;
	}

event dnp3_object_prefix(c: connection, is_orig: bool, prefix_value: count)
	{
	print "dnp3_object_prefix", is_orig, prefix_value;
	}

event dnp3_header_block(c: connection, is_orig: bool, start: count, len: count, ctrl: count, dest_addr: count, src_addr: count)
	{
	print "dnp3_header_block", is_orig, start, len, ctrl, dest_addr, src_addr;
	}

event dnp3_response_data_object(c: connection, is_orig: bool, data_value: count)
	{
	print "dnp3_response_data_object", is_orig, data_value;
	}

event dnp3_attribute_common(c: connection, is_orig: bool, data_type_code: count, leng: count, attribute_obj: string)
	{
        print "dnp3_attribute_common", is_orig, data_type_code, leng, attribute_obj;
	}

event dnp3_biewatime(c: connection, is_orig: bool, flag: count, time48: string)
	{
        print "dnp3_biewatime", is_orig, flag, time48;
	}

event dnp3_biewrtime(c: connection, is_orig: bool, flag: count, time16: count)
	{
        print "dnp3_biewrtime", is_orig, flag, time16;
	}

event dnp3_doublein_eveatime(c: connection, is_orig: bool, flag: count, time48: string)
	{
        print "dnp3_doublein_eveatime", is_orig, flag, time48;
	}
event dnp3_doublein_evertime(c: connection, is_orig: bool, flag: count, time16: count)
	{
        print "dnp3_doublein_evertime", is_orig, flag, time16;
	}

event dnp3_binout_eveatime(c: connection, is_orig: bool, flag: count, time48: string)
	{
        print "dnp3_binout_eveatime", is_orig, flag, time48;
	}

event dnp3_binoutcmd_eveatime(c: connection, is_orig: bool, flag: count, time48: string)
	{
        print "dnp3_binoutcmd_eveatime", is_orig, flag, time48;
	}

event dnp3_counterEve_32wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
	{
        print "dnp3_counterEve_32wFlag", is_orig, flag, count_value;
	}

event dnp3_counterEve_16wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
	{
        print "dnp3_counterEve_16wFlag", is_orig, flag, count_value;
	}

event dnp3_counterEve_32wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: string)
	{
        print "dnp3_counterEve_32wFlagTime", is_orig, flag, count_value, time48;
	}

event dnp3_counterEve_16wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: string)
	{
        print "dnp3_counterEve_16wFlagTime", is_orig, flag, count_value, time48;
	}

event dnp3_frozenCounterEve_32wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
	{
        print "dnp3_frozenCounterEve_32wFlag", is_orig, flag, count_value;
	}

event dnp3_frozenCounterEve_16wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
	{
        print "dnp3_frozenCounterEve_16wFlag", is_orig, flag, count_value;
	}

event dnp3_frozenCounterEve_32wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: string)
	{
        print "dnp3_frozenCounterEve_32wFlagTime", is_orig, flag, count_value, time48;
	}

event dnp3_frozenCounterEve_16wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: string)
	{
        print "dnp3_frozenCounterEve_16wFlagTime", is_orig, flag, count_value, time48;
	}

event dnp3_analog_output_status32(c: connection, is_orig: bool, flag: count, status: count)
	{
        print "dnp3_analog_output_status32", is_orig, flag, status;
	}

event dnp3_analog_output_status16(c: connection, is_orig: bool, flag: count, status: count)
	{
        print "dnp3_analog_output_status16", is_orig, flag, status;
	}

event dnp3_analog_output_statusSP(c: connection, is_orig: bool, flag: count, status: count)
	{
        print "dnp3_analog_output_statusSP", is_orig, flag, status;
	}

event dnp3_analog_output_statusDP(c: connection, is_orig: bool, flag: count, status_low: count, status_high: count)
	{
        print "dnp3_analog_output_statusDP", is_orig, flag, status_low, status_high;
	}

event dnp3_analog_output32(c: connection, is_orig: bool, value: count, con_status: count)
	{
        print "dnp3_analog_output32", is_orig, value, con_status;
	}

event dnp3_analog_output16(c: connection, is_orig: bool, value: count, con_status: count)
	{
        print "dnp3_analog_output16", is_orig, value, con_status;
	}

event dnp3_analog_outputSP(c: connection, is_orig: bool, value: count, con_status: count)
	{
        print "dnp3_analog_outputSP", is_orig, value, con_status;
	}

event dnp3_analog_outputDP(c: connection, is_orig: bool, value_low: count, value_high: count, con_status: count)
	{
        print "dnp3_analog_outputDP", is_orig, value_low, value_high, con_status;
	}

event dnp3_analog_output_event_32woTime(c: connection, is_orig: bool, flag: count, value: count)
	{
        print "dnp3_analog_output_event_32woTime", is_orig, flag, value;
	}

event dnp3_analog_output_event_16woTime(c: connection, is_orig: bool, flag: count, value: count)
	{
        print "dnp3_analog_output_event_16woTime", is_orig, flag, value;
	}

event dnp3_analog_output_event_32wTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
        print "dnp3_analog_output_event_32wTime", is_orig, flag, value, time48;
	}

event dnp3_analog_output_event_16wTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
        print "dnp3_analog_output_event_16wTime", is_orig, flag, value, time48;
	}

event dnp3_analog_output_event_SPwoTime(c: connection, is_orig: bool, flag: count, value: count)
	{
        print "dnp3_analog_output_event_SPwoTime", is_orig, flag, value;
	}

event dnp3_analog_output_event_DPwoTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
	{
        print "dnp3_analog_output_event_DPwoTime", is_orig, flag, value_low, value_high;
	}

event dnp3_analog_output_event_SPwTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
        print "dnp3_analog_output_eventSPwTime", is_orig, flag, value, time48;
	}

event dnp3_analog_output_event_DPwTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count, time48: string)
	{
        print "dnp3_analog_output_event_DPwTime", is_orig, flag, value_low, value_high, time48;
	}

event dnp3_abs_time(c: connection, is_orig: bool, time48: string)
	{
        print "dnp3_abs_time", is_orig, time48;
	}

event dnp3_abs_time_interval(c: connection, is_orig: bool, time48: string, interval32: count)
	{
        print "dnp3_abs_time_interval", is_orig, time48, interval32;
	}

event dnp3_last_abs_time(c: connection, is_orig: bool, time48: string)
	{
        print "dnp3_last_abs_time", is_orig, time48;
	}

event dnp3_record_obj(c: connection, is_orig: bool, record_size: count, record_oct: string)
	{
        print "dnp3_record_obj", is_orig, record_size, record_oct;
	}

event dnp3_file_control_id(c: connection, is_orig: bool, name_size: count, type_code: count, attr_code: count, start_rec: count, end_rec: count, file_size: count, time_create: string, permission: count, file_id: count, owner_id: count, group_id: count, function_code: count, status_code: count, file_name: string)
	{
        print "dnp3_doublein_evertime", is_orig, name_size, type_code, attr_code, start_rec, end_rec, file_size, time_create, permission, file_id, owner_id, group_id, function_code, status_code, file_name;
	}

event dnp3_file_control_auth(c: connection, is_orig: bool, usr_name_offset: count, usr_name_size: count, pwd_offset: count, pwd_size: count, auth_key: count, usr_name: string, pwd: string)
	{
        print "dnp3_doublein_evertime", is_orig, usr_name, usr_name_size, pwd_offset, pwd_size, auth_key, usr_name, pwd;
	}

event dnp3_file_control_cmd(c: connection, is_orig: bool, name_offset: count, name_size: count, time_create: string, permission: count, auth_key: count, file_size: count, op_mode: count, max_block_size: count, req_id: count, file_name: string)
	{
        print "dnp3_file_control_cmd", is_orig, name_offset, name_size, time_create, permission, auth_key, file_size, op_mode, max_block_size, req_id, file_name;
	}

event dnp3_file_control_cmd_status(c: connection, is_orig: bool, file_handle: count, file_size: count, max_block_size: count, req_id: count, status_code: count, opt_text: string)
	{
        print "dnp3_doublein_evertime", is_orig, file_handle, file_size, max_block_size, req_id, status_code, opt_text;
	}

event dnp3_file_transport_status(c: connection, is_orig:bool,  file_handle: count, block_num: count, status: count, opt_text: string)
	{
        print "dnp3_file_transport_status", is_orig, file_handle, block_num, status, opt_text;
	}

event dnp3_file_desc(c: connection, is_orig:bool, name_offset: count, name_size: count, f_type: count, f_size: count, time_create_low: count, time_create_high: count, permission: count, req_id: count, f_name: string)
	{
        print "dnp3_file_desc", is_orig, name_offset, name_size, f_type, f_size, time_create_low, time_create_high, permission, req_id, f_name;
	}

event dnp3_file_spec_str(c: connection, is_orig:bool, f_spec: string)
	{
        print "dnp3_file_spec_str", is_orig, f_spec;
	}

event dnp3_dev_store(c: connection, is_orig:bool, overflow: count, obj_group: count, variation: count)
	{
        print "dnp3_dev_store", is_orig, overflow, obj_group, variation;
	}

event dnp3_dev_profile(c: connection, is_orig:bool, fc_support_low: count, fc_support_high: count, count16: count)
	{
        print "dnp3_dev_profile", is_orig, fc_support_low, fc_support_high, count16;
	}

event dnp3_dev_profile_oh(c: connection, is_orig:bool, group: count, variation: count, qualifier: count, range: count)
	{
        print "dnp3_dev_profile", is_orig, group, variation, qualifier, range;
	}

event dnp3_priv_reg_obj(c: connection, is_orig:bool, vendor: count, obj_id: count, len: count, data_objs: string)
	{
        print "dnp3_priv_reg_obj", is_orig, vendor, obj_id, len, data_objs;
	}

event dnp3_priv_reg_obj_desc(c: connection, is_orig:bool, vendor: count, obj_id: count, count16: count)
	{
        print "dnp3_priv_reg_obj_desc", is_orig, vendor, obj_id, count16;
	}

event dnp3_obj_desc_spec(c: connection, is_orig:bool, obj_quantity: count, obj_group: count, obj_variation: count)
	{
        print "dnp3_obj_desc_spec", is_orig, obj_quantity, obj_group, obj_variation;
	}

event dnp3_desc_ele(c: connection, is_orig:bool, len: count, desc_code: count, data_type: count, max_len: count, aucillary: count)
	{
        print "dnp3_desc_ele", is_orig, len, desc_code, data_type, max_len, aucillary;
	}

event dnp3_app_id(c: connection, is_orig:bool, app_id_value: string)
	{
        print "dnp3_app_id", is_orig, app_id_value;
	}

event dnp3_activate_conf(c: connection, is_orig:bool, time_delay: count, count8: count)
	{
        print "dnp3_activate_conf", is_orig, time_delay, count8;
	}

event dnp3_status_ele(c: connection, is_orig:bool, len: count, status_code: count, ancillary: string)
	{
        print "dnp3_status_ele", is_orig, len, status_code, ancillary;
	}

event dnp3_bcd_large(c: connection, is_orig:bool, value_low: count, value_high: count)
	{
        print "dnp3_bcd_large", is_orig, value_low, value_high;
	}

event dnp3_auth_challenge(c: connection, is_orig:bool, csqUsr: count, hal: count, reason: count, chan_data: string)
	{
        print "dnp3_auth_challenge", is_orig, csqUsr, hal, reason, chan_data;
	}

event dnp3_auth_reply(c: connection, is_orig:bool, csqUsr: count, chan_data: string)
	{
        print "dnp3_auth_reply", is_orig, csqUsr, chan_data;
	}

event dnp3_auth_aggr_request(c: connection, is_orig:bool, csqUsr: count, chan_data: string)
	{
        print "dnp3_auth_aggr_request", is_orig, csqUsr, chan_data;
	}

event dnp3_auth_sessionkey_status(c: connection, is_orig:bool, csqUsr: count, key_alg: count, key_status: count, chan_data: string)
	{
        print "dnp3_auth_sessionkey_status", is_orig, csqUsr, key_alg, key_status, chan_data;
	}

event dnp3_auth_sessionkey_change(c: connection, is_orig:bool, csqUsr: count, key_wrap_data: string)
	{
        print "dnp3_auth_sessionkey_change", is_orig, csqUsr, key_wrap_data;
	}

event dnp3_auth_error(c: connection, is_orig:bool, csqUsr: count, error_code: count, key_wrap_data: string)
	{
        print "dnp3_auth_error", is_orig, csqUsr, error_code, key_wrap_data;
	}







event dnp3_crob(c:connection, is_orig: bool, control_code: count, count8: count, on_time: count, off_time: count, status_code: count)
	{
	print "dnp3_crob", is_orig, control_code, count8, on_time, off_time, status_code;
	}

event dnp3_pcb(c: connection, is_orig: bool, control_code: count, count8: count, on_time: count, off_time: count, status_code: count)
	{
	print "dnp3_pcb", is_orig, control_code, count8, on_time, off_time, status_code;
	}

event dnp3_counter_32wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
	{
	print "dnp3_counter_32wFlag", is_orig, flag, count_value;
	}

event dnp3_counter_16wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
	{
	print "dnp3_counter_16wFlag", is_orig, flag, count_value;
	}

event dnp3_counter_32woFlag(c: connection, is_orig: bool, count_value: count)
	{
	print "dnp3_counter_32woFlag", is_orig, count_value;
	}

event dnp3_counter_16woFlag(c: connection, is_orig: bool, count_value: count)
	{
	print "dnp3_counter_16woFlag", is_orig, count_value;
	}

event dnp3_frozen_counter_32wFlag(c: connection, is_orig: bool, flag:count, count_value: count)
	{
	print "dnp3_frozen_counter_32wFlag", is_orig, flag;
	}

event dnp3_frozen_counter_16wFlag(c: connection, is_orig: bool, flag:count, count_value: count)
	{
	print "dnp3_frozen_counter_16wFlag", is_orig, flag;
	}

event dnp3_frozen_counter_32wFlagTime(c: connection, is_orig: bool, flag:count, count_value: count, time48: string)
	{
	print "dnp3_frozen_counter_32wFlagTime", is_orig, flag;
	}

event dnp3_frozen_counter_16wFlagTime(c: connection, is_orig: bool, flag:count, count_value: count, time48: string)
	{
	print "dnp3_frozen_counter_16wFlagTime", is_orig, flag;
	}

event dnp3_frozen_counter_32woFlag(c: connection, is_orig: bool, count_value: count)
	{
	print "dnp3_frozen_counter_32woFlag", is_orig, count_value;
	}	

event dnp3_frozen_counter_16woFlag(c: connection, is_orig: bool, count_value: count)
	{
	print "dnp3_frozen_counter_16woFlag", is_orig, count_value;
	}

event dnp3_analog_input_32wFlag(c: connection, is_orig: bool, flag: count, value: count)
	{
	print "dnp3_analog_input_32wFlag", is_orig, flag, value;
	}

event dnp3_analog_input_16wFlag(c: connection, is_orig: bool, flag: count, value: count)
	{
	print "dnp3_analog_input_16wFlag", is_orig, flag, value;
	}

event dnp3_analog_input_32woFlag(c: connection, is_orig: bool, value: count)
	{
	print "dnp3_analog_input_32woFlag", is_orig, value;
	}

event dnp3_analog_input_16woFlag(c: connection, is_orig: bool, value: count)
	{
	print "dnp3_analog_input_16woFlag", is_orig, value;
	}

event dnp3_analog_input_SPwFlag(c: connection, is_orig: bool, flag: count, value: count)
	{
	print "dnp3_analog_input_SPwFlag", is_orig, flag, value;
	}

event dnp3_analog_input_DPwFlag(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
	{
	print "dnp3_analog_input_DPwFlag", is_orig, flag, value_low, value_high;
	}

event dnp3_frozen_analog_input_32wFlag(c: connection, is_orig: bool, flag: count, frozen_value: count)
	{
	print "dnp3_frozen_analog_input_32wFlag", is_orig, flag, frozen_value;
	}

event dnp3_frozen_analog_input_16wFlag(c: connection, is_orig: bool, flag: count, frozen_value: count)
	{
	print "dnp3_frozen_analog_input_16wFlag", is_orig, flag, frozen_value;
	}

event dnp3_frozen_analog_input_32wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: string)
	{
	print "dnp3_frozen_analog_input_32wTime", is_orig, flag, frozen_value, time48;
	}

event dnp3_frozen_analog_input_16wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: string)
	{
	print "dnp3_frozen_analog_input_16wTime", is_orig, flag, frozen_value, time48;
	}

event dnp3_frozen_analog_input_32woFlag(c: connection, is_orig: bool, frozen_value: count)
	{
	print "dnp3_frozen_analog_input_32woFlag", is_orig, frozen_value;
	}

event dnp3_frozen_analog_input_16woFlag(c: connection, is_orig: bool, frozen_value: count)
	{
	print "dnp3_frozen_analog_input_16woFlag", is_orig, frozen_value;
	}

event dnp3_frozen_analog_input_SPwFlag(c: connection, is_orig: bool, flag: count, frozen_value: count)
	{
	print "dnp3_frozen_analog_input_SPwFlag", is_orig, flag, frozen_value;
	}

event dnp3_frozen_analog_input_DPwFlag(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count)
	{
	print "dnp3_frozen_analog_input_DPwFlag", is_orig, flag, frozen_value_low, frozen_value_high;
	}

event dnp3_analog_input_event_32woTime(c: connection, is_orig: bool, flag: count, value: count)
	{
	print "dnp3_analog_input_event_32woTime", is_orig, flag, value;
	}

event dnp3_analog_input_event_16woTime(c: connection, is_orig: bool, flag: count, value: count)
	{
	print "dnp3_analog_input_event_16woTime", is_orig, flag, value;
	}

event dnp3_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
	print "dnp3_analog_input_event_32wTime", is_orig, flag, value, time48;
	}

event dnp3_analog_input_16wTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
	print "dnp3_analog_input_event_16wTime", is_orig, flag, value, time48;
	}

event dnp3_analog_inputSP_woTime(c: connection, is_orig: bool, flag: count, value: count)
	{
	print "dnp3_analog_input_event_SPwoTime", is_orig, flag, value;
	}

event dnp3_analog_inputDP_woTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
	{
	print "dnp3_analog_input_event_DPwoTime", is_orig, flag, value_low, value_high;
	}

event dnp3_analog_inputSP_wTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
	print "dnp3_analog_input_event_SPwTime", is_orig, flag, value, time48;
	}

event dnp3_analog_inputDP_wTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count, time48: string)
	{
	print "dnp3_analog_input_event_DPwTime", is_orig, flag, value_low, value_high, time48;
	}

event dnp3_frozen_analog_input_event_32woTime(c: connection, is_orig: bool, flag: count, frozen_value: count)
	{
	print "dnp3_frozen_analog_input_event_32woTime", is_orig, flag, frozen_value;
	}

event dnp3_frozen_analog_input_event_16woTime(c: connection, is_orig: bool, flag: count, frozen_value: count)
	{
	print "dnp3_frozen_analog_input_event_16woTime", is_orig, flag, frozen_value;
	}

event dnp3_frozen_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: string)
	{
	print "dnp3_frozen_analog_input_event_32wTime", is_orig, flag, frozen_value, time48;
	}

event dnp3_frozen_analog_input_event_16wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: string)
	{
	print "dnp3_frozen_analog_input_event_16wTime", is_orig, flag, frozen_value, time48;
	}

event dnp3_frozen_analog_input_event_SPwoTime(c: connection, is_orig: bool, flag: count, frozen_value: count)
	{
	print "dnp3_frozen_analog_input_event_SPwoTime", is_orig, flag, frozen_value;
	}

event dnp3_frozen_analog_input_event_DPwoTime(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count)
	{
	print "dnp3_frozen_analog_input_event_DPwoTime", is_orig, flag, frozen_value_low, frozen_value_high;
	}

event dnp3_frozen_analog_input_event_SPwTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: string)
	{
	print "dnp3_frozen_analog_inputeventSP_wTime", is_orig, flag, frozen_value, time48;
	}

event dnp3_frozen_analog_input_event_DPwTime(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count, time48: string)
	{
	print "dnp3_frozen_analog_inputeventDP_wTime", is_orig, flag, frozen_value_low, frozen_value_high, time48;
	}

event dnp3_file_transport(c: connection, is_orig: bool, file_handle: count, block_num: count, file_data: string)
	{
        print "dnp3_file_transport", is_orig, file_handle, block_num;
        print hexdump(file_data);
	}

event dnp3_debug_byte(c: connection, is_orig: bool, debug: string)
{
	print "dnp3_debug_byte", is_orig, debug;
}


