# @TEST-DOC: Packed double-bit binary inputs (g3v1) take two bits per point, so the object after them and the next request are seen.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-packed-double-bit-inputs.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m dnp3.log
# @TEST-EXEC: test ! -e analyzer.log

@load base/protocols/conn
@load base/protocols/dnp3
@load base/frameworks/analyzer/logging

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	print c$id$orig_p, is_orig ? "request" : "response", fmt("0x%04x", obj_type), fmt("0x%02x", qua_field), number, rf_low, rf_high;
	}
