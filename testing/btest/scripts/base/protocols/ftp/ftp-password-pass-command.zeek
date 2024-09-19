# @TEST-DOC: Adding PASS to logged commands should log the password in password and arg column
# @TEST-EXEC: zeek -b -Cr $TRACES/ftp/ftp-password-pass-command.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: test ! -f reporter.log

@load base/protocols/conn
@load base/protocols/ftp

redef FTP::logged_commands += { "USER", "PASS", "SYST", "QUIT" };

redef FTP::default_capture_password = T;