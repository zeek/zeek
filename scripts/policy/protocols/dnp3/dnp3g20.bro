event dnp3_counter32_wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
	print fmt("dnp3 g20v1 object: flag: 0x%x, count_value: %d ", flag, count_value);
}

event dnp3_counter16_wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
	print fmt("dnp3 g20v2 object: flag: 0x%x, count_value: %d ", flag, count_value);
}

event dnp3_counter32_woFlag(c: connection, is_orig: bool, count_value: count)
{
	print fmt("dnp3 g20v5 object: count_value: %d ", count_value);
}

event dnp3_counter16_woFlag(c: connection, is_orig: bool, count_value: count)
{
	print fmt("dnp3 g20v6 object: count_value: %d ", count_value);
}
