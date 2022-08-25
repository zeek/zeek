# This tests both active and passive FTP over IPv6.
#
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv6.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log

@load base/protocols/conn
@load base/protocols/ftp
