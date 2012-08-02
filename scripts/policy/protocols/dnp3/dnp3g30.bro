#### Including different event for response objects


event dnp3_analog_input32_wFlag(c: connection, is_orig: bool, flag: count, value: count)
	{
        print fmt("dnp3 response analog 32 bit with flag. flag: %x, value: %x ", flag, value);
        }
event dnp3_analog_input16_wFlag(c: connection, is_orig: bool, flag: count, value: count)
	{
        print fmt("dnp3 response analog 16 bit with flag. flag: %x, value: %x ", flag, value);
        }
event dnp3_analog_input32_woFlag(c: connection, is_orig: bool, value: count)
	{
        print fmt("dnp3 response analog 32 bit without flag. value: %x ", value);
        }
event dnp3_analog_input16_woFlag(c: connection, is_orig: bool, value: count)
	{
        print fmt("dnp3 response analog 16 bit without flag. value: %d ", value);
        }
event dnp3_analog_inputSP_wFlag(c: connection, is_orig: bool, flag: count, value: count)
	{
        print fmt("dnp3 response analog single precision with flag. flag: %x, value: %x ", flag, value);
        }
event dnp3_analog_inputDP_wFlag(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
	{
        print fmt("dnp3 response analog double precision with flag. flag: %x, value_low: %x value_high: %x ", flag, value_low, value_high);
        }


