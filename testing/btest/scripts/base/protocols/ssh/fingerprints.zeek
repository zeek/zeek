# @TEST-EXEC: zeek -r $TRACES/ssh/ssh1-ssh2-fingerprints.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/ssh

event ssh2_server_host_key(c: connection, key: string)
	{
	print "ssh2 server host key fingerprint",  md5_hash(key);
	}

event ssh1_server_host_key(c: connection, modulus: string, exponent: string)
	{
	print "ssh1 server host key fingerprint", md5_hash(modulus + exponent);
	}

event ssh_server_host_key(c: connection, hash: string)
	{
	print "ssh server host key fingerprint", hash;
	}
