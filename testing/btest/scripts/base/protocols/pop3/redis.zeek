# @TEST-DOC: The POP3 signature triggered on Redis traffic. Ensure the analyzer is eventually removed to avoid.
# @TEST-EXEC: zeek -C -b -r $TRACES/pop3/redis-50-pings.pcap %INPUT >out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff analyzer_debug.log

@load frameworks/analyzer/debug-logging.zeek
@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/pop3

redef POP3::max_unknown_client_commands = 3;

event pop3_request(c: connection, is_orig: bool, cmd: string, arg: string)
	{
	print c$uid, "pop3_request", is_orig, cmd, arg;
	}

event pop3_reply(c: connection, is_orig: bool, cmd: string, arg: string)
	{
	print c$uid, "pop3_reply", is_orig, cmd, arg;
	}
