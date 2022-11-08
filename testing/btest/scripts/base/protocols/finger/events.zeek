# @TEST-EXEC: zeek -r $TRACES/finger/standard.pcap %INPUT >>output
# @TEST-EXEC: zeek -r $TRACES/finger/verbose.pcap %INPUT >>output
# @TEST-EXEC: btest-diff output

global resp_lines = 0;

event finger_request(c: connection, full: bool, username: string, hostname: string)
	{
	print "request", c$id, full, username, hostname;
	}

event finger_reply(c: connection, reply_line: string)
	{
	if ( ++resp_lines >= 5 )
		return;

	print "response", c$id, reply_line;
	}
