#
# @TEST-EXEC: bro -r $TRACES/modbus.trace %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat output | awk '{print $1}' | sort | uniq | wc -l >covered
# @TEST-EXEC: cat ${DIST}/src/event.bif  | grep "^event modbus_" | wc -l >total
# @TEST-EXEC: echo `cat covered` of `cat total` events triggered by trace >coverage
# @TEST-EXEC: btest-diff coverage

event modbus_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count)
{
	print "modbus_request", is_orig, tid, pid, uid, fc;
}

event modbus_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count)
{
	print "modbus_response", is_orig, tid, pid, uid, fc;
}

event modbus_read_coils_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, bcount: count)
{
	print "modbus_read_coils_request", is_orig, tid, pid, uid, fc, ref, bcount;
}

event modbus_read_input_discretes_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, bcount: count)
{
	print "modbus_read_input_discretes_request", is_orig, tid, pid, uid, fc, ref, bcount;
}

event modbus_read_multi_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, wcount: count, len: count)
{
	print "modbus_read_multi_request", is_orig, tid, pid, uid, fc, ref, wcount, len;
}

event modbus_read_input_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, wcount: count, len: count)
{
	print "modbus_read_input_request", is_orig, tid, pid, uid, fc, ref, wcount, len;
}

event modbus_write_coil_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, onOff: count, other: count)
{
	print "modbus_write_coil_request", is_orig, tid, pid, uid, fc, ref, onOff, other;
}

event modbus_write_single_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, len: count, ref: count, value: count)
{
	print "modbus_write_single_request", is_orig, tid, pid, uid, fc, len, ref, value;
}

event modbus_force_coils_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, bitCount: count, byteCount: count, coils: string)
{
	print "modbus_force_coils_request", is_orig, tid, pid, uid, fc, ref, bitCount, byteCount, coils;
}

event modbus_write_multi_request(c: connection, is_orig: bool, t: int_vec, tid: count, pid: count, uid: count, fc: count, ref: count, wCount: count, bCount: count, len: count)
{
	print "modbus_write_multi_request", is_orig, t, tid, pid, uid, fc, ref, wCount, bCount, len;
}

event modbus_read_reference_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, refCount: count, t: int_vec)
{
	print "modbus_read_reference_request", is_orig, tid, pid, uid, fc, refCount, t;
}

event modbus_read_single_reference_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, refType: count, refNumber: count, wordCount: count)
{
	print "modbus_read_single_reference_request", is_orig, tid, pid, uid, fc, refType, refNumber, wordCount;
}

event modbus_write_reference_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, byteCount: count, t: int_vec)
{
	print "modbus_write_reference_request", is_orig, tid, pid, uid, fc, byteCount, t;
}

event modbus_write_single_reference(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, refType: count, refNumber: count, wordCount: count, t: int_vec)
{
	print "modbus_write_single_reference", is_orig, tid, pid, uid, fc, refType, refNumber, wordCount, t;
}

event modbus_mask_write_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, andMask: count, orMask: count)
{
	print "modbus_mask_write_request", is_orig, tid, pid, uid, fc, ref, andMask, orMask;
}

event modbus_read_write_request(c: connection, is_orig: bool, t: int_vec, tid: count, pid: count, uid: count, fc: count, refRead: count, wcRead: count, refWrite: count, wcWrite: count, bCount: count, len: count)
{
	print "modbus_read_write_request", is_orig, t, tid, pid, uid, fc, refRead, wcRead, refWrite, wcWrite, bCount, len;
}

event modbus_read_FIFO_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count)
{
	print "modbus_read_FIFO_request", is_orig, tid, pid, uid, fc, ref;
}

event modbus_read_except_request(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, len: count)
{
	print "modbus_read_except_request", is_orig, tid, pid, uid, fc, len;
}

event modbus_read_coils_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, bcount: count, bits: string)
{
	print "modbus_read_coils_response", is_orig, tid, pid, uid, fc, bcount, bits;
}

event modbus_read_input_discretes_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, bcount: count, bits: string)
{
	print "modbus_read_input_discretes_response", is_orig, tid, pid, uid, fc, bcount, bits;
}

event modbus_read_multi_response(c: connection, is_orig: bool, t: int_vec, tid: count, pid: count, uid: count, fc: count, bCount: count, len: count)
{
	print "modbus_read_multi_response", is_orig, t, tid, pid, uid, fc, bCount, len;
}

event modbus_read_input_response(c: connection, is_orig: bool, t: int_vec, tid: count, pid: count, uid: count, fc: count, bCount: count, len: count)
{
	print "modbus_read_input_response", is_orig, t, tid, pid, uid, fc, bCount, len;
}

event modbus_write_coil_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, onOff: count, other: count)
{
	print "modbus_write_coil_response", is_orig, tid, pid, uid, fc, ref, onOff, other;
}

event modbus_write_single_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, len: count, ref: count, value: count)
{
	print "modbus_write_single_response", is_orig, tid, pid, uid, fc, len, ref, value;
}

event modbus_force_coils_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, bitCount: count)
{
	print "modbus_force_coils_response", is_orig, tid, pid, uid, fc, ref, bitCount;
}

event modbus_write_multi_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, wcount: count, len: count)
{
	print "modbus_write_multi_response", is_orig, tid, pid, uid, fc, ref, wcount, len;
}

event modbus_read_reference_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, byteCount: count, t: int_vec)
{
	print "modbus_read_reference_response", is_orig, tid, pid, uid, fc, byteCount, t;
}

event modbus_read_single_reference_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, byteCount: count, refType: count, t: int_vec)
{
	print "modbus_read_single_reference_response", is_orig, tid, pid, uid, fc, byteCount, refType, t;
}

event modbus_write_reference_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, byteCount: count, t: int_vec)
{
	print "modbus_write_reference_response", is_orig, tid, pid, uid, fc, byteCount, t;
}

event modbus_mask_write_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, ref: count, andMask: count, orMask: count)
{
	print "modbus_mask_write_response", is_orig, tid, pid, uid, fc, ref, andMask, orMask;
}

event modbus_read_write_response(c: connection, is_orig: bool, t: int_vec, tid: count, pid: count, uid: count, fc: count, bCount: count, len: count)
{
	print "modbus_read_write_response", is_orig, t, tid, pid, uid, fc, bCount, len;
}

event modbus_read_FIFO_response(c: connection, is_orig: bool, t: int_vec, tid: count, pid: count, uid: count, fc: count, bcount: count)
{
	print "modbus_read_FIFO_response", is_orig, t, tid, pid, uid, fc, bcount;
}

event modbus_read_except_response(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, status: count, len: count)
{
	print "modbus_read_except_response", is_orig, tid, pid, uid, fc, status, len;
}

event modbus_exception(c: connection, is_orig: bool, tid: count, pid: count, uid: count, fc: count, code: count)
{
	print "modbus_exception", is_orig, tid, pid, uid, fc, code;
}

