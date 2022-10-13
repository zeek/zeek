# @TEST-DOC: In the pcap, the server responds with 10 unknown server commands and analyzer_violation_info events are raised for each. Verify that setting max_analyzer_violations creates a weird and suppresses further analyzer violation events.

# @TEST-EXEC: zeek -b -r $TRACES/pop3-unknown-commands.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/pop3
@load base/frameworks/notice/weird

# It would trigger 10
redef max_analyzer_violations = 5;

# Do not let DPD logic interfere with this test.
redef DPD::ignore_violations += { Analyzer::ANALYZER_POP3 };

global c = 0;

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print ++c, "violation", atype, info$c$uid, info$aid, info$reason;
	}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
	{
	print "request", c$uid, command, arg;
	}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
	{
	print "reply", c$uid, cmd, msg;
	}
