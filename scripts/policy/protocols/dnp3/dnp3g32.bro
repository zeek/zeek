#### Including different event for response objects


event dnp3_analog_input32_woTime(c: connection, is_orig: bool, flag: count, value: count)
	{
	print fmt("dnp3 response analog 16 bit without time. flag: %x, value: %x ", flag, value);
	}
event dnp3_analog_input16_woTime(c: connection, is_orig: bool, flag: count, value: count)
        {
        print fmt("dnp3 response analog 16 bit without time. flag: %x, value: %x ", flag, value);
        }
event dnp3_analog_input32_wTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
	print fmt("dnp3 response analog 32 bit with time. flag: %x, value: %x ", flag, value);
	print hexdump(time48);
	}
event dnp3_analog_input16_wTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
        print fmt("dnp3 response analog 16 bit with time. flag: %x, value: %x ", flag, value);
        print hexdump(time48);
        }
event dnp3_analog_inputSP_woTime(c: connection, is_orig: bool, flag: count, value: count)
	{
        print fmt("dnp3 response analog single precision without time. flag: %x, value: %x ", flag, value);
        }	
event dnp3_analog_inputDP_woTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
	{
        print fmt("dnp3 response analog double precision without time. flag: %x, value_low: %x. value_high: %x ", flag, value_low, value_high);
        }
event dnp3_analog_inputSP_wTime(c: connection, is_orig: bool, flag: count, value: count, time48: string)
	{
        print fmt("dnp3 response analog single precision with time. flag: %x, value: %x ", flag, value);
        print hexdump(time48);
        }
event dnp3_analog_inputDP_wTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count, time48: string)
	{
        print fmt("dnp3 response analog double precision with time. flag: %x, value_low: %x, value_high: %x ", flag, value_low, value_high);
        print hexdump(time48);
        }




