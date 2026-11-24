# @TEST-DOC: Over UDP, a request and a response too short for their application header are reported with a weird and dropped, and the analyzer keeps decoding the flow.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-short-app-fragment-udp.pcap %INPUT >output
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test ! -e analyzer.log

@load base/protocols/dnp3
@load base/frameworks/analyzer/dpd
@load base/frameworks/analyzer/logging

# READ 0 and READ 1 ask for group 30 points 0 and 1; the 41004 filler READs ask
# for points 100 and above and are not printed.
event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	if ( rf_low < 100 )
		print c$id$orig_p, is_orig ? "request" : "response", obj_type, rf_low;
	}

global weirds: table[port, string, string] of count &default=0 &ordered;

event conn_weird(name: string, c: connection, addl: string, source: string)
	{
	++weirds[c$id$orig_p, name, addl];
	}

event zeek_done()
	{
	for ( [p, name, addl], n in weirds )
		print p, name, addl, n;
	}
