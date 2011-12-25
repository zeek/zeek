event dnp3_crob(c: connection, is_orig: bool, control_code: count, count8: count, on_time: count, off_time: count, status_code: count)
{
	print fmt("dnp3 g12v1 object: control_code: 0x%x, count: %d, on_time: 0x%x, off_time: 0x%x, status_code: 0x%x ", control_code, count8, on_time, off_time, status_code);
}
event dnp3_pcb(c: connection, is_orig: bool, control_code: count, count8: count, on_time: count, off_time: count, status_code: count)
{
	print fmt("dnp3 g12v2 object: control_code: 0x%x, count: %d, on_time: 0x%x, off_time: 0x%x, status_code: 0x%x ", control_code, count8, on_time, off_time, status_code);
}
