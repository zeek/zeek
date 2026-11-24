# @TEST-DOC: Over UDP, the analyzer applies the same pseudo-transport rules: a repeated or stray segment is ignored and a frame with a bad data CRC is dropped, in requests and responses.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-transport-rules-udp.pcap %INPUT >output
#
# @TEST-EXEC: btest-diff-cut -m id.orig_p fc_request fc_reply dnp3.log
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test ! -e analyzer.log

@load base/protocols/dnp3
@load base/frameworks/notice/weird
@load base/frameworks/analyzer/logging

# Each READ asks for group 30 point n (start = stop = n), so the decoded object
# headers show which READs, and which response, the analyzer accepted.
event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	print c$id$orig_p, is_orig ? "request" : "response", obj_type, rf_low;
	}

# weird.log collapses repeated weirds per connection: count the events.
global weirds: table[port, string] of count &default=0 &ordered;

event conn_weird(name: string, c: connection, addl: string, source: string)
	{
	++weirds[c$id$orig_p, name];
	}

event zeek_done()
	{
	for ( [p, name], n in weirds )
		print p, name, n;
	}
