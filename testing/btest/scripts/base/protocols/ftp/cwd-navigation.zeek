# @TEST-EXEC: zeek -b -r $TRACES/ftp/cwd-navigation.pcap >output.log %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff output.log

@load base/protocols/conn
@load base/protocols/ftp

# Make sure we're tracking the CWD correctly.
event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=10
	{
	if ( ! c?$ftp )
		return;

	print "CWD", c$ftp$cwd;
	}


