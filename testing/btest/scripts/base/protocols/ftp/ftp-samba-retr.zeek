# @TEST-DOC: Tests interemediate lines to not confuse cwd tracking.
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv6-retr-samba.trace %INPUT > out
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load base/protocols/ftp

redef FTP::logged_commands += { "USER", "PASS", "RETR" };

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) {
	print "ftp_reply", cont_resp, code, cat(c$ftp$reply_msg);
}
