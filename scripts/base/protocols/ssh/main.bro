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
		result: string &log &optional;
		## Auth method (password, pubkey, etc.)
		method: string &log &optional;
		## Direction of the connection. If the client was a local host
		## logging into an external host, this would be OUTBOUND. INBOUND
		## would be set for the opposite situation.
		## TODO: handle local-local and remote-remote better.
		direction: Direction &log &optional;
		## The client's version string
		client: string &log &optional;
		## The server's version string
		server: string &log &optional;
		## The server's key fingerprint
		host_key: string &log &optional;
		## This connection has been logged (internal use)
		logged: bool &default=F;
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

const ports = { 22/tcp };

event bro_init() &priority=5
	{
	Log::create_stream(SSH::LOG, [$columns=Info, $ev=log_ssh]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSH, ports);
	}

function determine_auth_method(version: int, last_pkt_len: int, middle_pkt_len: int, first_pkt_len: int): string
	{
	# This is still being tested.
	# Based on "Analysis for Identifying User Authentication Methods on SSH Connections"
	# by Satoh, Nakamura, Ikenaga.

	if ( version == 2 )
		{
		if ( first_pkt_len == 0 )
			return "none";
		if ( middle_pkt_len == 96 )
			return "password";
		if ( middle_pkt_len == 16 )
			return "gssapi";
		if ( ( middle_pkt_len == 32 ) && ( first_pkt_len == 0 || first_pkt_len == 48 ) )
			return "challenge-response";
		if ( middle_pkt_len < 256 )
			return fmt("unknown (mid=%d, first=%d)", middle_pkt_len, first_pkt_len);	
		if ( first_pkt_len == 16 )
			return "host-based";
		return fmt("pubkey (~%d bits)", (first_pkt_len - 16)*8);
		}
	else if ( version == 1 )
		{
		if ( first_pkt_len == 0 )
			return "password";
		if ( first_pkt_len >= 96 && first_pkt_len <= 256 )
			return fmt("pubkey (~%d bits)", first_pkt_len * 8);
		return fmt("%d %d %d", first_pkt_len, middle_pkt_len, last_pkt_len);
		}
	}	

event ssh_server_version(c: connection, version: string)
	{
	if ( !c?$ssh )
		{
		local s: SSH::Info;
		s$ts  = network_time();
		s$uid = c$uid;
		s$id  = c$id;
		c$ssh = s;
		}
	c$ssh$server = version;
	}

event ssh_client_version(c: connection, version: string)
	{
	if ( !c?$ssh )
		{
		local s: SSH::Info;
		s$ts  = network_time();
		s$uid = c$uid;
		s$id  = c$id;
		c$ssh = s;
		}
	c$ssh$client = version;
	if ( version[4] == "1" )
		c$ssh$version = 1;
	if ( version[4] == "2" )
		c$ssh$version = 2;
	}

event ssh_auth_successful(c: connection, last_pkt_len: int, middle_pkt_len: int, first_pkt_len: int)
	{
	print "ssh_auth_successful";
	if ( !c?$ssh || ( c$ssh?$result && c$ssh$result == "success" ) )
		return;
	c$ssh$result = "success";
	c$ssh$method = determine_auth_method(c$ssh$version, last_pkt_len, middle_pkt_len, first_pkt_len);
	}

event ssh_auth_successful(c: connection, last_pkt_len: int, middle_pkt_len: int, first_pkt_len: int) &priority=-5
	{
	c$ssh$logged = T;
	Log::write(SSH::LOG, c$ssh);	
	}
	
event ssh_auth_failed(c: connection, last_pkt_len: int, middle_pkt_len: int, first_pkt_len: int)
	{
	print "ssh_auth_failed";
	if ( !c?$ssh || ( c$ssh?$result && c$ssh$result == "success" ) )
		return;
	c$ssh$result = "failure";
	c$ssh$method = determine_auth_method(c$ssh$version, last_pkt_len, middle_pkt_len, first_pkt_len);
	}
	
event ssh_auth_failed(c: connection, last_pkt_len: int, middle_pkt_len: int, first_pkt_len: int) &priority=-5
	{
	c$ssh$logged = T;
	Log::write(SSH::LOG, c$ssh);
	}

event connection_state_remove(c: connection)
	{
	if ( c?$ssh && !c$ssh?$result )
		{
		c$ssh$result = "unknown";
		}
	}

event ssh_server_capabilities(c: connection, kex_algorithms: string, server_host_key_algorithms: string, encryption_algorithms_client_to_server: string, encryption_algorithms_server_to_client: string, mac_algorithms_client_to_server: string, mac_algorithms_server_to_client: string, compression_algorithms_client_to_server: string, compression_algorithms_server_to_client: string, languages_client_to_server: string, languages_server_to_client: string)
	{
	# print "kex_algorithms", kex_algorithms;
	# print "";
	# print "server_host_key_algorithms", server_host_key_algorithms;
	# print "";
	# print "encryption_algorithms_client_to_server", encryption_algorithms_client_to_server;
	# print "";
	# print "encryption_algorithms_server_to_client", encryption_algorithms_server_to_client;
	# print "";
	# print "mac_algorithms_client_to_server", mac_algorithms_client_to_server;
	# print "";
	# print "mac_algorithms_server_to_client", mac_algorithms_server_to_client;
	# print "";
	# print "compression_algorithms_client_to_server", compression_algorithms_client_to_server;
	# print "";
	# print "compression_algorithms_server_to_client", compression_algorithms_server_to_client;
	# print "";
	# print "languages_client_to_server", languages_client_to_server;
	# print "";
	# print "languages_server_to_client", languages_server_to_client;
	# print "";
	}
	
event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$ssh && !c$ssh$logged )
		Log::write(SSH::LOG, c$ssh);
	}
	
function generate_fingerprint(c: connection, key: string)
	{
	local lx = str_split(md5_hash(key), vector(2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30));
	lx[0] = "";
	c$ssh$host_key = sub(join_string_vec(lx, ":"), /:/, "");
	}

event ssh1_server_host_key(c: connection, p: string, e: string)
	{
	if ( !c?$ssh )
		return;
	generate_fingerprint(c, e + p);
	}

event ssh_server_host_key(c: connection, key: string)
	{
	if ( !c?$ssh )
		return;
	generate_fingerprint(c, key);
	}

