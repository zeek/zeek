# @TEST-DOC: DNP3 resynchronization rejects false headers, handles split starts and response-side gaps, reports once per recovery episode, and gives up after the resync skip budget.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-tcp-gap-resync.pcap %INPUT >output
#
# @TEST-EXEC: btest-diff-cut -m dnp3.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
# @TEST-EXEC: test ! -e analyzer.log
# @TEST-EXEC: btest-diff output

@load base/protocols/dnp3
@load base/frameworks/notice/weird
@load base/frameworks/analyzer/logging

# weird.log collapses repeated weirds per connection, so count the events to
# check that two gaps in one resync episode raise dnp3_gap_resync only once,
# and that only the over-budget connections (40018, 40020) give up.
global dnp3_weirds: table[port, string] of count &default=0 &ordered;

event conn_weird(name: string, c: connection, addl: string, source: string)
	{
	if ( name == "dnp3_gap_resync" || name == "dnp3_resync_failed" )
		++dnp3_weirds[c$id$orig_p, name];
	}

event zeek_done()
	{
	for ( [p, name], n in dnp3_weirds )
		print p, name, n;
	}
