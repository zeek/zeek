# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/bif/event.bif.zeek
@load base/protocols/ssh

module SSH;

# Creates a mock connection. This connection is good enough for e.g.,
# `SSH::set_version`, but not in line with what Zeek considers active
# connections.
function make_conn(server: string, client: string): connection
	{
	local c: connection;
	c$uid = "uid";

	local id: conn_id;
	id$orig_h = 127.0.0.1;
	id$resp_h = 127.0.0.1;
	id$orig_p = 40/tcp;
	id$resp_p = 40/tcp;
	c$id = id;

	local ssh: SSH::Info;
	ssh$ts = network_time();
	ssh$server = server;
	ssh$client = client;
	c$ssh = ssh;

	SSH::set_session(c);

	delete c$ssh$version;
	return c;
	}

# While `SSH::set_version` triggers a `conn_weird` we are dealing with mock
# connections which since they are injected are always considered expired by
# Zeek.
event expired_conn_weird(name: string, id: conn_id, uid: string, addl: string, source: string)
	{
	print "conn_weird:", name, id, addl, source;
	}

const v1 = "SSH-1.5-OpenSSH_6.2";
const v199 = "SSH-1.99-OpenSSH_3.1p1";
const v2 = "SSH-2.0-OpenSSH_5.9";

event zeek_init()
	{
	local c: connection;

	# Good cases.
		{
		# SSH1 vs SSH1 -> 1.
		c = make_conn(v1, v1);
		SSH::set_version(c);
		print "SSH1 vs SSH1", c$ssh$version;

		# SSH199 vs SSH1 -> 1.
		c = make_conn(v1, v199);
		SSH::set_version(c);
		print "SSH199 vs SSH1", c$ssh$version; # 1.

		# SSH2 vs SSH2 -> 2.
		c = make_conn(v2, v2);
		SSH::set_version(c);
		print "SSH2 vs SSH2", c$ssh$version; # 2.

		# SSH199 vs SSH2 -> 2.
		c = make_conn(v2, v199);
		SSH::set_version(c);
		print "SSH199 vs SSH2", c$ssh$version; # 2.
		}

	# Error cases.
		{
		# Unset vs unset -> unset.
		c = make_conn("", "");
		c$ssh$version = 42;
		SSH::set_version(c);
		print "unset vs unset", c$ssh?$version; # Unset.

		# Client unset.
		c = make_conn(v2, "");
		c$ssh$version = 42;
		SSH::set_version(c);
		print "client unset", c$ssh?$version; # Unset.

		# Server unset.
		c = make_conn("", v2);
		c$ssh$version = 42;
		SSH::set_version(c);
		print "server unset", c$ssh?$version; # Unset.

		# Unable to extract full server version.
		c = make_conn("SSH", v1);
		c$ssh$version = 42;
		SSH::set_version(c);
		print "incomplete server version", c$ssh?$version;

		# Unable to extract full client version.
		c = make_conn(v1, "SSH");
		c$ssh$version = 42;
		SSH::set_version(c);
		print "incomplete client version", c$ssh?$version;

		# SSH1 vs SSH2.
		c = make_conn(v1, v2);
		SSH::set_version(c);
		print "SSH1 vs SSH2", c$ssh?$version; # Unset.

		# SSH2 vs SSH1.
		c = make_conn(v2, v1);
		SSH::set_version(c);
		print "SSH2 vs SSH1", c$ssh?$version; # Unset.
		}
	}
