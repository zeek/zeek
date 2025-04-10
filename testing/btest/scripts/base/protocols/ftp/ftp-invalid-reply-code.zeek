# @TEST-DOC: The server replies with a line that does not contain a numeric code: violation.
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ftp-invalid-reply-code.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff analyzer_failed.log
# @TEST-EXEC: test ! -f reporter.log

@load base/protocols/conn
@load base/protocols/ftp

redef FTP::logged_commands += { "USER", "PASS", "SYST", "QUIT" };
