# This tests both active and passive FTP over IPv6.
#
# @TEST-EXEC: zeek -r $TRACES/ftp/ipv6.trace
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log

