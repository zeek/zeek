# This tests explicit TLS.
#
# @TEST-EXEC: zeek -r $TRACES/ftp/ftp-auth-tls.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff ssl.log

redef FTP::logged_commands += { "<init>", "AUTH" };
