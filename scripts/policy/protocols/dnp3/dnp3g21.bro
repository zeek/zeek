event dnp3_frozen_counter32_wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
	print fmt("dnp3 g21v1 object: flag: 0x%x, count_value: %d ", flag, count_value);
}

event dnp3_frozen_counter16_wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
	print fmt("dnp3 g21v2 object: flag: 0x%x, count_value: %d ", flag, count_value);
}

event dnp3_frozen_counter32_wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: string)
{
	print fmt("dnp3 g21v2 object: flag: 0x%x, count_value: %d ", flag, count_value);
	print hexdump(time48);	
}

event dnp3_frozen_counter16_wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: string)
{
	print fmt("dnp3 g21v2 object: flag: 0x%x, count_value: %d ", flag, count_value);
	print hexdump(time48);
}
event dnp3_frozen_counter32_woFlag(c: connection, is_orig: bool, count_value: count)
{
	print fmt("dnp3 g21v9 object: count_value: %d ", count_value);
}

event dnp3_frozen_counter16_woFlag(c: connection, is_orig: bool, count_value: count)
{
	print fmt("dnp3 g21v10 object: count_value: %d ", count_value);
}
