# @TEST-DOC: In the pcap, the server responds with 10 unknown server commands and analyzer_violation_info events are raised for each. Verify that setting max_analyzer_violations creates a weird and suppresses further analyzer violation events.

# @TEST-EXEC: zeek -b -r $TRACES/pop3-unknown-commands.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/pop3
@load base/frameworks/notice/weird

# It would trigger 10
redef max_analyzer_violations = 5;

global c = 0;

event analyzer_violation(con: connection, atype: AllAnalyzers::Tag, aid: count, reason: string)
	{
	print ++c, "violation", atype, con$uid, aid, reason;
	}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
	{
	print "request", c$uid, command, arg;
	}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
	{
	print "reply", c$uid, cmd, msg;
	}
