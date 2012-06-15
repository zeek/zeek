# This tests both active and passive FTP over IPv6.
#
# @TEST-EXEC: bro -r $TRACES/ipv6-ftp.trace
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log

