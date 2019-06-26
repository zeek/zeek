# @TEST-EXEC: zeek -r $TRACES/ftp/cwd-navigation.pcap >output.log %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff output.log

# Make sure we're tracking the CWD correctly.
event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=10
	{
	print "CWD", c$ftp$cwd;
	}


