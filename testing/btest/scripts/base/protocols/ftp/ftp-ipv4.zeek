# This tests both active and passive FTP over IPv4.
#
# @TEST-EXEC: zeek -r $TRACES/ftp/ipv4.trace
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log

