# @TEST-DOC: Artificially generated pcap where the FTP client sends a batch of commands before the server ever responds with a ready message. Cap max_pending_commands at 5 and verify generation of weird.log and no scripting errors.
#
# @TEST-EXEC: zeek -b -r $TRACES/ftp/fake-server-delays-all.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: test ! -f reporter.log

@load base/protocols/conn
@load base/protocols/ftp

redef FTP::max_pending_commands = 5;
redef FTP::logged_commands += { "USER", "SYST" };

event ftp_request(c: connection, command: string, arg: string)
	{
	print "ftp_request", c$uid, command, arg;
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	print "ftp_reply", c$uid, code, msg;
	}
