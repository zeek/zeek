##! Implements base functionality for SSH analysis. Generates the ssh.log file.

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;
		## SSH major version (1 or 2)
		version: count &log;
		## Auth result
		auth_success: bool &log &optional;

		## Auth details
		auth_details: string &log &optional;
		## Direction of the connection. If the client was a local host
		## logging into an external host, this would be OUTBOUND. INBOUND
		## would be set for the opposite situation.
		## TODO: handle local-local and remote-remote better.
		direction: Direction &log &optional;
		## The encryption algorithm in use
		cipher_alg: string &log &optional;
		## The signing (MAC) algorithm in use
		mac_alg: string &log &optional;
		## The compression algorithm in use
		compression_alg: string &log &optional;
		## The key exchange algorithm in use
		kex_alg: string &log &optional;

		## The server host key's algorithm
		host_key_alg: string &log &optional;
		## The server's key fingerprint
		host_key: string &log &optional;
		## The client's version string
		client: string &log &optional;
		## The server's version string
		server: string &log &optional;
		
		## This connection has been logged (internal use)
		logged: bool &default=F;
		## Number of failures seen (internal use)
		num_failures: count &default=0;
		## Store capabilities from the first host for
		## comparison with the second (internal use)
		capabilities: Capabilities &optional;
	};

	## If true, we tell the event engine to not look at further data
	## packets after the initial SSH handshake. Helps with performance
	## (especially with large file transfers) but precludes some
	## kinds of analyses.
	const skip_processing_after_detection = F &redef;
	
	## Event that can be handled to access the SSH record as it is sent on
	## to the logging framework.
	global log_ssh: event(rec: Info);
}

redef record connection += {
	ssh: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(SSH::LOG, [$columns=Info, $ev=log_ssh]);
	}


function init_record(c: connection)
	{
	local s: SSH::Info;
	s$ts  = network_time();
	s$uid = c$uid;
	s$id  = c$id;
	c$ssh = s;
	}
	

event ssh_server_version(c: connection, version: string)
	{
	if ( !c?$ssh )
		init_record(c);
		
	c$ssh$server = version;
	}

event ssh_client_version(c: connection, version: string)
	{
	if ( !c?$ssh )
		init_record(c);
		
	c$ssh$client = version;
	
	if ( version[4] == "1" )
		c$ssh$version = 1;
	if ( version[4] == "2" )
		c$ssh$version = 2;
	}

event ssh_auth_successful(c: connection, auth_method_none: bool)
	{
	if ( !c?$ssh || ( c$ssh?$auth_success && c$ssh$auth_success ) )
		return;

	# We can't accurately tell for compressed streams
	if ( c$ssh?$compression_alg && ( c$ssh$compression_alg == "zlib@openssh.com" ||
	   	 						     c$ssh$compression_alg == "zlib" ) )
		return;
		
	c$ssh$auth_success = T;

	if ( auth_method_none )
		c$ssh$auth_details = "method: none";

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
	
event ssh_auth_failed(c: connection)
	{
	if ( !c?$ssh || ( c$ssh?$auth_success && !c$ssh$auth_success ) )
		return;

	# We can't accurately tell for compressed streams
	if ( c$ssh?$compression_alg && ( c$ssh$compression_alg == "zlib@openssh.com" ||
	   	 						     c$ssh$compression_alg == "zlib" ) )
		return;

	c$ssh$auth_success = F;
	c$ssh$num_failures += 1;
	}

function array_to_vec(s: string_array): vector of string
	{
	local r: vector of string;
	
	for (i in s)
		r[i] = s[i];
	return r;
	}
	
function find_client_preferred_algorithm(client_algorithms: vector of string, server_algorithms: vector of string): string
	{
	for ( i in client_algorithms )
		for ( j in server_algorithms )
			if ( client_algorithms[i] == server_algorithms[j] )
				return client_algorithms[i];
	}
	
function find_client_preferred_algorithm_bidirectional(client_algorithms_c_to_s: vector of string,
		 											   server_algorithms_c_to_s: vector of string,
		 											   client_algorithms_s_to_c: vector of string,
													   server_algorithms_s_to_c: vector of string): string
	{
	local c_to_s = find_client_preferred_algorithm(client_algorithms_c_to_s, server_algorithms_c_to_s);
	local s_to_c = find_client_preferred_algorithm(client_algorithms_s_to_c, server_algorithms_s_to_c);

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

	c$ssh$cipher_alg = find_client_preferred_algorithm_bidirectional(client_caps$encryption_algorithms_client_to_server,
																	 server_caps$encryption_algorithms_client_to_server,
																	 client_caps$encryption_algorithms_server_to_client,
																	 server_caps$encryption_algorithms_server_to_client);
																
	c$ssh$mac_alg = find_client_preferred_algorithm_bidirectional(client_caps$mac_algorithms_client_to_server,
																  server_caps$mac_algorithms_client_to_server,
															  	  client_caps$mac_algorithms_server_to_client,
															  	  server_caps$mac_algorithms_server_to_client);
																 
	c$ssh$compression_alg = find_client_preferred_algorithm_bidirectional(client_caps$compression_algorithms_client_to_server,
																		  server_caps$compression_algorithms_client_to_server,
															          	  client_caps$compression_algorithms_server_to_client,
															          	  server_caps$compression_algorithms_server_to_client);

	c$ssh$kex_alg = find_client_preferred_algorithm(client_caps$kex_algorithms, server_caps$kex_algorithms);	
	c$ssh$host_key_alg = find_client_preferred_algorithm(client_caps$server_host_key_algorithms,
														 server_caps$server_host_key_algorithms);
	}
	
event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$ssh && !c$ssh$logged && c$ssh?$client && c$ssh?$server )
		{
		if ( c$ssh?$auth_success && !c$ssh$auth_success )
		   c$ssh$auth_details = fmt("%d failure%s", c$ssh$num_failures, c$ssh$num_failures == 1 ? "" : "s");
		   
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

event ssh1_server_host_key(c: connection, p: string, e: string)
	{
	generate_fingerprint(c, e + p);
	}

event ssh_server_host_key(c: connection, key: string)
	{
	generate_fingerprint(c, key);
	}

