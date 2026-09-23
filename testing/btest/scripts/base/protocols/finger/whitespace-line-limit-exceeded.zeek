# @TEST-DOC: Ensures Finger request whitespace is covered by the line limit.
#
# @TEST-EXEC: zeek -b -r $TRACES/finger/whitespace-line-limit.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-canonifier-spicy btest-diff-cut -m analyzer_debug.log

@load base/protocols/finger
@load frameworks/analyzer/debug-logging

event finger_request(c: connection, full: bool, username: string, hostname: string)
	{
	print "BAD: overlong whitespace produced a request event", c$id, full, username, hostname;
	}

event zeek_done()
	{
	print "done";
	}
