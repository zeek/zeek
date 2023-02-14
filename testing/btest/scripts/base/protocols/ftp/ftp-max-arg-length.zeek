# Test truncation of the arg field in the ftp.log.
#
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv4.trace %INPUT
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/conn
@load base/protocols/ftp

redef FTP::logged_commands += { "CWD", "USER" };
redef FTP::max_arg_length = 13;
redef FTP::max_reply_msg_length = 17;
