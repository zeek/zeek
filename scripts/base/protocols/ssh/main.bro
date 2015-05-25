##! Implements base functionality for SSH analysis. Generates the ssh.log file.

@load base/utils/directions-and-hosts

module SSH;

export {
	## The SSH protocol logging stream identifier.
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time when the SSH connection began.
		ts:              time         &log;
		## Unique ID for the connection.
		uid:             string       &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:              conn_id      &log;
		## SSH major version (1 or 2)
		version:         count        &log;
		## Authentication result (T=success, F=failure, unset=unknown)
		auth_success:    bool         &log &optional;
		## Direction of the connection. If the client was a local host
		## logging into an external host, this would be OUTBOUND. INBOUND
		## would be set for the opposite situation.
		# TODO - handle local-local and remote-remote better.
		direction:       Direction    &log &optional;
		## The client's version string
		client:          string       &log &optional;
		## The server's version string
		server:          string       &log &optional;
		## The encryption algorithm in use
		cipher_alg:      string       &log &optional;
		## The signing (MAC) algorithm in use
		mac_alg:         string       &log &optional;
		## The compression algorithm in use
		compression_alg: string       &log &optional;
		## The key exchange algorithm in use
		kex_alg:         string       &log &optional;
		## The server host key's algorithm
		host_key_alg:    string       &log &optional;
		## The server's key fingerprint
		host_key:        string       &log &optional;
	};

	## The set of compression algorithms. We can't accurately determine
	## authentication success or failure when compression is enabled.
	const compression_algorithms = set("zlib", "zlib@openssh.com") &redef;

	## If true, we tell the event engine to not look at further data
	## packets after the initial SSH handshake. Helps with performance
	## (especially with large file transfers) but precludes some
	## kinds of analyses. Defaults to T.
	const skip_processing_after_detection = T &redef;

	## Event that can be handled to access the SSH record as it is sent on
	## to the logging framework.
	global log_ssh: event(rec: Info);

	## Event that can be handled when the analyzer sees an SSH server host
	## key. This abstracts :bro:id:`ssh1_server_host_key` and
	## :bro:id:`ssh2_server_host_key`.
	global ssh_server_host_key: event(c: connection, hash: string);
}

redef record Info += {
	# This connection has been logged (internal use)
	logged:       bool         &default=F;
	# Number of failures seen (internal use)
	num_failures: count        &default=0;
	# Store capabilities from the first host for
	# comparison with the second (internal use)
	capabilities: Capabilities &optional;
};

redef record connection += {
	ssh: Info &optional;
};

const ports = { 22/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSH, ports);
	Log::create_stream(SSH::LOG, [$columns=Info, $ev=log_ssh, $path="ssh"]);
	}

function set_session(c: connection)
	{
	if ( ! c?$ssh )
		{
		local info: SSH::Info;
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;

		# If both hosts are local or non-local, we can't reliably set a direction.
		if ( Site::is_local_addr(c$id$orig_h) != Site::is_local_addr(c$id$resp_h) )
			info$direction = Site::is_local_addr(c$id$orig_h) ? OUTBOUND: INBOUND;
		c$ssh = info;
		}
	}

event ssh_server_version(c: connection, version: string)
	{
	set_session(c);
	c$ssh$server = version;
	}

event ssh_client_version(c: connection, version: string)
	{
	set_session(c);
	c$ssh$client = version;

	if ( ( |version| > 3 ) && ( version[4] == "1" ) )
		c$ssh$version = 1;
	if ( ( |version| > 3 ) && ( version[4] == "2" ) )
		c$ssh$version = 2;
	}

event ssh_auth_successful(c: connection, auth_method_none: bool) &priority=5
	{
	# TODO - what to do here?
	if ( !c?$ssh || ( c$ssh?$auth_success && c$ssh$auth_success ) )
		return;

	# We can't accurately tell for compressed streams
	if ( c$ssh?$compression_alg && ( c$ssh$compression_alg in compression_algorithms ) )
		return;

	c$ssh$auth_success = T;

	if ( skip_processing_after_detection)
		{
		skip_further_processing(c$id);
		set_record_packets(c$id, F);
		}
	}

event ssh_auth_successful(c: connection, auth_method_none: bool) &priority=-5
	{
	if ( c?$ssh && !c$ssh$logged )
		{
		c$ssh$logged = T;
		Log::write(SSH::LOG, c$ssh);
		}
	}

event ssh_auth_failed(c: connection) &priority=5
	{
	if ( !c?$ssh || ( c$ssh?$auth_success && !c$ssh$auth_success ) )
		return;

	# We can't accurately tell for compressed streams
	if ( c$ssh?$compression_alg && ( c$ssh$compression_alg in compression_algorithms ) )
		return;

	c$ssh$auth_success = F;
	c$ssh$num_failures += 1;
	}

# Determine the negotiated algorithm
function find_alg(client_algorithms: vector of string, server_algorithms: vector of string): string
	{
	for ( i in client_algorithms )
		for ( j in server_algorithms )
			if ( client_algorithms[i] == server_algorithms[j] )
				return client_algorithms[i];
	return "Algorithm negotiation failed";
	}

# This is a simple wrapper around find_alg for cases where client to server and server to client
# negotiate different algorithms. This is rare, but provided for completeness.
function find_bidirectional_alg(client_prefs: Algorithm_Prefs, server_prefs: Algorithm_Prefs): string
	{
	local c_to_s = find_alg(client_prefs$client_to_server, server_prefs$client_to_server);
	local s_to_c = find_alg(client_prefs$server_to_client, server_prefs$server_to_client);

	# Usually these are the same, but if they're not, return the details
	return c_to_s == s_to_c ? c_to_s : fmt("To server: %s, to client: %s", c_to_s, s_to_c);
	}
	
event ssh_capabilities(c: connection, cookie: string, capabilities: Capabilities)
	{
	if ( !c?$ssh || ( c$ssh?$capabilities && c$ssh$capabilities$is_server == capabilities$is_server ) )
		return;

	if ( !c$ssh?$capabilities )
		{
		c$ssh$capabilities = capabilities;
		return;
		}

	local client_caps = capabilities$is_server ? c$ssh$capabilities : capabilities;
	local server_caps = capabilities$is_server ? capabilities : c$ssh$capabilities;

	c$ssh$cipher_alg      = find_bidirectional_alg(client_caps$encryption_algorithms,
	                                               server_caps$encryption_algorithms);
	c$ssh$mac_alg         = find_bidirectional_alg(client_caps$mac_algorithms,
	                                               server_caps$mac_algorithms);
	c$ssh$compression_alg = find_bidirectional_alg(client_caps$compression_algorithms,
	                                               server_caps$compression_algorithms);
	c$ssh$kex_alg         = find_alg(client_caps$kex_algorithms, server_caps$kex_algorithms);	
	c$ssh$host_key_alg    = find_alg(client_caps$server_host_key_algorithms,
	                                 server_caps$server_host_key_algorithms);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$ssh && !c$ssh$logged && c$ssh?$client && c$ssh?$server )
		{
		c$ssh$logged = T;
		Log::write(SSH::LOG, c$ssh);
		}
	}

function generate_fingerprint(c: connection, key: string)
	{
	if ( !c?$ssh )
		return;

	local lx = str_split(md5_hash(key), vector(2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30));
	lx[0] = "";
	c$ssh$host_key = sub(join_string_vec(lx, ":"), /:/, "");
	}

event ssh1_server_host_key(c: connection, p: string, e: string) &priority=5
	{
	generate_fingerprint(c, e + p);
	}

event ssh2_server_host_key(c: connection, key: string) &priority=5
	{
	generate_fingerprint(c, key);
	}
