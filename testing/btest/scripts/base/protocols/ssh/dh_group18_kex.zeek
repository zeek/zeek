# @TEST-DOC: Verify diffie-hellman-group18-sha512 is recognized as a fixed-group DH key exchange.
#
# @TEST-EXEC: zeek -b -r $TRACES/ssh/ssh_kex_dh_group18.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m ssh.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
#
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/frameworks/notice/weird

event ssh2_dh_gex_init(c: connection, is_orig: bool)
	{
	print "ssh2_dh_gex_init", is_orig;
	}

event ssh2_server_host_key(c: connection, key: string)
	{
	print "ssh2_server_host_key", |key|;
	}
