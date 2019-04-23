#
# @TEST-EXEC: zeek -r $TRACES/dnp3/dnp3.trace %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat output | awk '{print $1}' | sort | uniq | wc -l >covered
# @TEST-EXEC: cat ${DIST}/src/analyzer/protocol/dnp3/events.bif  | grep "^event dnp3_" | wc -l >total
# @TEST-EXEC: echo `cat covered` of `cat total` events triggered by trace >coverage
# @TEST-EXEC: btest-diff coverage
# @TEST-EXEC: btest-diff dnp3.log
#
event dnp3_application_request_header(c: connection, is_orig: bool, application_control: count, fc: count)
	{
	print "dnp3_application_request_header", is_orig, application_control, fc;
	}

event dnp3_application_response_header(c: connection, is_orig: bool, application_control: count, fc: count, iin: count)
	{
	print "dnp3_application_response_header", is_orig, application_control, fc, iin;
	}

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	print "dnp3_object_header", is_orig, obj_type, qua_field, number, rf_low, rf_high;
	}

event dnp3_object_prefix(c: connection, is_orig: bool, prefix_value: count)
	{
	print "dnp3_object_prefix", is_orig, prefix_value;
	}

event dnp3_header_block(c: connection, is_orig: bool, len: count, ctrl: count, dest_addr: count, src_addr: count)
	{
	print "dnp3_header_block", is_orig, len, ctrl, dest_addr, src_addr;
	}

event dnp3_response_data_object(c: connection, is_orig: bool, data_value: count)
	{
	print "dnp3_response_data_object", is_orig, data_value;
	}

event dnp3_attribute_common(c: connection, is_orig: bool, data_type_code: count, leng: count, attribute_obj: string)
	{
        print "dnp3_attribute_common", is_orig, data_type_code, leng, attribute_obj;
	}

event dnp3_crob(c: connection, is_orig: bool, control_code: count, count8: count, on_time: count, off_time: count, status_code: count)
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

event dnp3_frozen_counter_32wFlagTime(c: connection, is_orig: bool, flag:count, count_value: count, time48: count)
	{
	print "dnp3_frozen_counter_32wFlagTime", is_orig, flag;
	}

event dnp3_frozen_counter_16wFlagTime(c: connection, is_orig: bool, flag:count, count_value: count, time48: count)
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

event dnp3_frozen_analog_input_32wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
	{
	print "dnp3_frozen_analog_input_32wTime", is_orig, flag, frozen_value, time48;
	}

event dnp3_frozen_analog_input_16wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
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

event dnp3_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
	{
	print "dnp3_analog_input_event_32wTime", is_orig, flag, value, time48;
	}

event dnp3_analog_input_16wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
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

event dnp3_analog_inputSP_wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
	{
	print "dnp3_analog_input_event_SPwTime", is_orig, flag, value, time48;
	}

event dnp3_analog_inputDP_wTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count, time48: count)
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

event dnp3_frozen_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
	{
	print "dnp3_frozen_analog_input_event_32wTime", is_orig, flag, frozen_value, time48;
	}

event dnp3_frozen_analog_input_event_16wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
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

event dnp3_frozen_analog_input_event_SPwTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
	{
	print "dnp3_frozen_analog_inputeventSP_wTime", is_orig, flag, frozen_value, time48;
	}

event dnp3_frozen_analog_input_event_DPwTime(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count, time48: count)
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


