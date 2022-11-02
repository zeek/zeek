##! Implements base functionality for SSH analysis. Generates the ssh.log file.

@load base/utils/directions-and-hosts
@load base/protocols/conn/removal-hooks

module SSH;

export {
	## The SSH protocol logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type which contains the fields of the SSH log.
	type Info: record {
		## Time when the SSH connection began.
		ts:              time         &log;
		## Unique ID for the connection.
		uid:             string       &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:              conn_id      &log;
		## SSH major version (1, 2, or unset). The version can be unset if the
		## client and server version strings are unset, malformed or incompatible
		## so no common version can be extracted. If no version can be extracted
		## even though both client and server versions are set a weird
		## will be generated.
		version:         count        &log &optional;
		## Authentication result (T=success, F=failure, unset=unknown)
		auth_success:    bool         &log &optional;
		## The number of authentication attempts we observed. There's always
		## at least one, since some servers might support no authentication at all.
		## It's important to note that not all of these are failures, since
		## some servers require two-factor auth (e.g. password AND pubkey)
		auth_attempts:   count        &log &default=0;
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
	option compression_algorithms = set("zlib", "zlib@openssh.com");

	## If true, after detection detach the SSH analyzer from the connection
	## to prevent continuing to process encrypted traffic. Helps with performance
	## (especially with large file transfers).
	option disable_analyzer_after_detection = T;

	## Event that can be handled to access the SSH record as it is sent on
	## to the logging framework.
	global log_ssh: event(rec: Info);

	## SSH finalization hook.  Remaining SSH info may get logged when it's called.
	global finalize_ssh: Conn::RemovalHook;
}

module GLOBAL;
export {
	## This event is generated when an :abbr:`SSH (Secure Shell)`
	## connection was determined to have had a failed authentication. This
	## determination is based on packet size analysis, and errs on the
	## side of caution - that is, if there's any doubt about the
	## authentication failure, this event is *not* raised.
	##
	## This event is only raised once per connection.
	##
	## c: The connection over which the :abbr:`SSH (Secure Shell)`
	##    connection took place.
	##
	## .. zeek:see:: ssh_server_version ssh_client_version
	##    ssh_auth_successful ssh_auth_result ssh_auth_attempted
	##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
	##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
	##    ssh2_gss_error ssh2_ecc_key
	global ssh_auth_failed: event(c: connection);

	## This event is generated when a determination has been made about
	## the final authentication result of an :abbr:`SSH (Secure Shell)`
	## connection. This determination is based on packet size analysis,
	## and errs on the side of caution - that is, if there's any doubt
	## about the result of the authentication, this event is *not* raised.
	##
	## This event is only raised once per connection.
	##
	## c: The connection over which the :abbr:`SSH (Secure Shell)`
	##    connection took place.
	##
	## result: True if the authentication was successful, false if not.
	##
	## auth_attempts: The number of authentication attempts that were
	##    observed.
	##
	## .. zeek:see:: ssh_server_version ssh_client_version
	##    ssh_auth_successful ssh_auth_failed ssh_auth_attempted
	##    ssh_capabilities ssh2_server_host_key ssh1_server_host_key
	##    ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
	##    ssh2_gss_error ssh2_ecc_key
	global ssh_auth_result: event(c: connection, result: bool, auth_attempts: count);
}

module SSH;

redef record Info += {
	# This connection has been logged (internal use)
	logged:       bool         &default=F;
	# Store capabilities from the first host for
	# comparison with the second (internal use)
	capabilities: Capabilities &optional;
	## Analyzer ID
	analyzer_id: count         &optional;
};

redef record connection += {
	ssh: Info &optional;
};

const ports = { 22/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSH, ports);
	Log::create_stream(SSH::LOG, [$columns=Info, $ev=log_ssh, $path="ssh", $policy=log_policy]);
	}

function set_session(c: connection)
	{
	if ( ! c?$ssh )
		{
		local info: SSH::Info &is_assigned;	# needed for $version
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;

		# If both hosts are local or non-local, we can't reliably set a direction.
		if ( Site::is_local_addr(c$id$orig_h) != Site::is_local_addr(c$id$resp_h) )
			info$direction = Site::is_local_addr(c$id$orig_h) ? OUTBOUND: INBOUND;
		c$ssh = info;
		Conn::register_removal_hook(c, finalize_ssh);
		}
	}

function set_version(c: connection)
	{
	# We always either set the version field to a concrete value, or unset it.
	delete c$ssh$version;

	# If either the client or server string is unset we cannot compute a
	# version and return early. We do not raise a weird in this case as we
	# might arrive here while having only seen one side of the handshake.
	const has_server = c$ssh?$server && |c$ssh$server| > 0;
	const has_client = c$ssh?$client && |c$ssh$client| > 0;
	if ( ! ( has_server && has_client ) )
		return;

	if ( |c$ssh$client| > 4 && |c$ssh$server| > 4 )
		{
		if ( c$ssh$client[4] == "1" && c$ssh$server[4] == "2" )
			{
			# SSH199 vs SSH2 -> 2
			if ( ( |c$ssh$client| > 7 ) && ( c$ssh$client[6] == "9" ) && ( c$ssh$client[7] == "9" ) )
				c$ssh$version = 2;
			# SSH1 vs SSH2 -> Undefined
			else
				Reporter::conn_weird("SSH_version_mismatch", c, fmt("%s vs %s", c$ssh$server, c$ssh$client));
				return;
			}
		else if ( c$ssh$client[4] == "2" && c$ssh$server[4] == "1" )
			{
			# SSH2 vs SSH199 -> 2
			if ( ( |c$ssh$server| > 7 ) && ( c$ssh$server[6] == "9" ) && ( c$ssh$server[7] == "9" ) )
				c$ssh$version = 2;
			else
				# SSH2 vs SSH1 -> Undefined
				Reporter::conn_weird("SSH_version_mismatch", c, fmt("%s vs %s", c$ssh$server, c$ssh$client));
				return;
			}
		else if ( c$ssh$client[4] == "1" && c$ssh$server[4] == "1" )
			{
			# SSH1 vs SSH199 -> 1
			if ( ( |c$ssh$server| > 7 ) && ( c$ssh$server[6] == "9" ) && ( c$ssh$server[7] == "9" ) )
				{
				# SSH199 vs SSH199
				if (( |c$ssh$client| > 7 ) && ( c$ssh$client[6] == "9" ) && ( c$ssh$client[7] == "9" ))
					c$ssh$version = 2;
				else
					c$ssh$version = 1;
				}
			else
				{
				# SSH1 vs SSH1 -> 1
				c$ssh$version = 1;
				}
			}
		# SSH2 vs SSH2
		else if (c$ssh$client[4] == "2" && c$ssh$server[4] == "2" )
			{
			c$ssh$version = 2;
			}

		return;
		}

	Reporter::conn_weird("SSH_cannot_determine_version", c, fmt("%s vs %s", c$ssh$server, c$ssh$client));
	}

event ssh_server_version(c: connection, version: string)
	{
	set_session(c);
	c$ssh$server = version;
	set_version(c);
	}

event ssh_client_version(c: connection, version: string)
	{
	set_session(c);
	c$ssh$client = version;
	set_version(c);
	}

event ssh_auth_attempted(c: connection, authenticated: bool) &priority=5
	{
	if ( !c?$ssh || ( c$ssh?$auth_success && c$ssh$auth_success ) )
		return;

	# We can't accurately tell for compressed streams
	if ( c$ssh?$compression_alg && ( c$ssh$compression_alg in compression_algorithms ) )
		return;

	c$ssh$auth_success = authenticated;
	c$ssh$auth_attempts += 1;

	if ( authenticated && disable_analyzer_after_detection )
		disable_analyzer(c$id, c$ssh$analyzer_id);
	}

event ssh_auth_attempted(c: connection, authenticated: bool) &priority=-5
	{
	if ( authenticated && c?$ssh && !c$ssh$logged )
		{
		event ssh_auth_result(c, authenticated, c$ssh$auth_attempts);
		c$ssh$logged = T;
		Log::write(SSH::LOG, c$ssh);
		}
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

hook finalize_ssh(c: connection)
	{
	if ( ! c?$ssh )
		return;

	if ( c$ssh$logged )
		return;

	# Do we have enough information to make a determination about auth success?
	if ( c$ssh?$client && c$ssh?$server && c$ssh?$auth_success )
		{
		# Successes get logged immediately. To protect against a race condition, we'll double check:
		if ( c$ssh$auth_success )
			return;

		# Now that we know it's a failure, we'll raise the event.
		event ssh_auth_failed(c);
		}
	# If not, we'll just log what we have
	else
		{
		c$ssh$logged = T;
		Log::write(SSH::LOG, c$ssh);
		}
	}

event ssh_auth_failed(c: connection) &priority=-5
	{
	# This should not happen; prevent double-logging just in case
	if ( ! c?$ssh || c$ssh$logged )
		return;

	c$ssh$logged = T;
	Log::write(SSH::LOG, c$ssh);

	event ssh_auth_result(c, F, c$ssh$auth_attempts);
	}

event ssh_server_host_key(c: connection, hash: string) &priority=5
	{
	if ( ! c?$ssh )
		return;

	c$ssh$host_key = hash;
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=20
	{
	if ( atype == Analyzer::ANALYZER_SSH )
		{
		set_session(info$c);
		info$c$ssh$analyzer_id = info$aid;
		}
	}
