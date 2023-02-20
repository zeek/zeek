# @TEST-DOC: Tests that c$ftp$reply_msg stays the same over a multiline reply.
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv6-multiline-reply.trace %INPUT > out
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load base/protocols/ftp

redef FTP::logged_commands += { "<init>", "USER", "PASS" };

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) {
	print "ftp_reply", cont_resp, code, cat(c$ftp$reply_msg);
}
