# @TEST-DOC: Device attributes (g0v196-v210, g0v244) are parsed in responses and WRITE requests, so their values and the objects after them are seen.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-device-attributes.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m dnp3.log
# @TEST-EXEC: test ! -e analyzer.log
# @TEST-EXEC: test ! -e weird.log

@load base/protocols/conn
@load base/protocols/dnp3
@load base/frameworks/notice/weird
@load base/frameworks/analyzer/logging

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	print c$id$orig_p, is_orig ? "request" : "response", fmt("0x%04x", obj_type), fmt("0x%02x", qua_field), number;
	}

event dnp3_attribute_common(c: connection, is_orig: bool, data_type_code: count, leng: count, attribute_obj: string)
	{
	local value = data_type_code == 1 ? attribute_obj : bytestring_to_hexstr(attribute_obj);
	print c$id$orig_p, is_orig ? "request" : "response", "attribute", data_type_code, leng, value;
	}
