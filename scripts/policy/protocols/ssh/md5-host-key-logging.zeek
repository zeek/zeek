##! Adds MD5 host_key field to ssh.log

@load base/protocols/ssh

module SSH;

export {
	redef record Info += {
		## The server's key fingerprint
		host_key:        string       &log &optional;
	};
}

event ssh_server_host_key(c: connection, hash: string) &priority=5
	{
	if ( ! c?$ssh )
		return;

	c$ssh$host_key = hash;
	}
