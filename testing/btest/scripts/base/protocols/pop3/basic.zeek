# @TEST-DOC: Ensure basic POP3 functionality.
# @TEST-EXEC: zeek -b -r $TRACES/pop3/pop3.pcap %INPUT >out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: test ! -f analyzer.log

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/pop3

event pop3_request(c: connection, is_orig: bool, cmd: string, arg: string)
	{
	print c$uid, "pop3_request", is_orig, cmd, arg;
	}

event pop3_reply(c: connection, is_orig: bool, cmd: string, arg: string)
	{
	print c$uid, "pop3_reply", is_orig, cmd, arg;
	}
