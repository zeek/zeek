# @TEST-DOC: The analyzer applies the pseudo-transport FIR and sequence rules: a FIR segment restarts the fragment, a segment without application octets is skipped, and a segment that does not continue the fragment in progress is dropped without stopping the analyzer.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-transport-rules.pcap %INPUT >output
#
# @TEST-EXEC: btest-diff-cut -m id.orig_p fc_request fc_reply dnp3.log
# @TEST-EXEC: btest-diff-cut -m id.orig_p name weird.log
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test ! -e analyzer.log

@load base/protocols/dnp3
@load base/frameworks/notice/weird
@load base/frameworks/analyzer/logging

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	if ( is_orig )
		print c$id$orig_p, obj_type, rf_low;
	}
