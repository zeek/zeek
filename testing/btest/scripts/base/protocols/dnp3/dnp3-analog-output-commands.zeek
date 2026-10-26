# @TEST-DOC: Analog output blocks (g41v1-v4) in requests are parsed with their own sizes, so later requests and responses are seen.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-analog-output-commands.pcap %INPUT >output
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
	print c$id$orig_p, is_orig ? "request" : "response", fmt("0x%04x", obj_type), fmt("0x%02x", qua_field), number;
	}

event dnp3_crob(c: connection, is_orig: bool, control_code: count, count8: count, on_time: count, off_time: count, status_code: count)
	{
	print c$id$orig_p, is_orig ? "request" : "response", "crob", control_code, count8, status_code;
	}
