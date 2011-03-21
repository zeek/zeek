##! SSL connections

@load functions
@load notice

@load ssl-ciphers
@load ssl-errors

module SSL;

redef enum Notice::Type += {
	# Blanket X509 error
	SSL_X509Violation,
	## Session data not consistent with connection
	SSL_SessConIncon,
};

redef enum Log::ID += { SSL };

export {
	type Log: record {
		ts:                     time;
		id:                     conn_id;
		## This is the session ID.  It's optional because SSLv2 doesn't have it.
		sid:                    string &optional;
		# TODO: dga 3/11 The following 2 fields are not yet picked up
		#not_valid_before:       time;               # certificate valid time constraint
		#not_valid_after:        time;               # certificate valid time constraint
		version:                string &default="UNKNOWN"; # version number
		weak_client_cipher:     bool &default = F;  # true if client offered insecure ciphers
		weak_server_cipher:     bool &default = F;  # true if server offered insecure ciphers
		weak_cipher_agreed:     bool &default = F;  # true if insecure cipher agreed upon for use
		
		version:                string &default=""; # version associated with connection
		client_cert:            X509 &optional;     # client certificate
		server_cert:            X509 &optional;     # server certificate
		handshake_cipher:       string &default=""; # agreed-upon cipher for session/conn.
	};
	
	type ConnectionInfo: record {
		log:      Log;
		
	};

	type SessionInfo: record {
		## This tracks the number of times this session has been reused.
		num_reuse:  count &default=1;
		
		version:                string &default=""; # version associated with connection
		client_cert:            X509 &optional;     # client certificate
		server_cert:            X509 &optional;     # server certificate
		handshake_cipher:       string &default=""; # agreed-upon cipher for session/conn.
	};

	# Certificates presented by which hosts to record.
	# Choices are: LocalHosts, RemoteHosts, Enabled, Disabled
	const logging = LocalHosts &redef;

	# If set to T, this will split local and remote certs
	# into separate files.  F merges everything into a single file.
	#const split_log_file = F &redef;
	
	# If true, Bro stores the client and server cipher specs and performs
	# additional tests.  This costs an extra amount of memory (normally
	# only for a short time) but enables detecting of non-intersecting
	# cipher sets, for example.
	const ssl_compare_cipherspecs = T &redef;
	
	# Whether to analyze certificates seen in SSL connections.
	const ssl_analyze_certificates = T &redef;
	
	# If we analyze SSL certificates, we can choose to store them.
	const ssl_store_certificates = T &redef;
	
	# Path where we dump the certificates into.  If it's empty,
	# use the current directory.
	const ssl_store_cert_path = "certs" &redef;
	
	# If we analyze SSL certificates, we can choose to verify them.
	const ssl_verify_certificates = T &redef;
	
	# This is the path where OpenSSL looks after the trusted certificates.
	# If empty, the default path will be used.
	const x509_trusted_cert_path = "" &redef;
	
	# Whether to store key-material exchanged in the handshaking phase.
	const ssl_store_key_material = F &redef;
	
	## The list of all detected X509 certs.
	global certs: set[addr, port, string] &create_expire=1day &synchronized;

	## All active SSL/TLS connections
	global active_conns: table[conn_id] of ConnectionInfo &read_expire=1hr;

	## Recent TLS session IDs
	global recent_sessions: table[string] of SessionInfo &read_expire=1hr;
	
	global log_ssl: event(rec: Log);
	
	## This is the set of SSL/TLS ciphers are are seen as weak to attack.
	const weak_ciphers: set[count] = {
		SSLv20_CK_RC4_128_EXPORT40_WITH_MD5,
		SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
		SSLv20_CK_DES_64_CBC_WITH_MD5,

		TLS_NULL_WITH_NULL_NULL,
		TLS_RSA_WITH_NULL_MD5,
		TLS_RSA_WITH_NULL_SHA,
		TLS_RSA_EXPORT_WITH_RC4_40_MD5,
		TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
		TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
		TLS_RSA_WITH_DES_CBC_SHA,

		TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
		TLS_DH_DSS_WITH_DES_CBC_SHA,
		TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
		TLS_DH_RSA_WITH_DES_CBC_SHA,
		TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
		TLS_DHE_DSS_WITH_DES_CBC_SHA,
		TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
		TLS_DHE_RSA_WITH_DES_CBC_SHA,

		TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5,
		TLS_DH_ANON_WITH_RC4_128_MD5,
		TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
		TLS_DH_ANON_WITH_DES_CBC_SHA,
		TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA,
	} &redef;
	
	const SSLv2  = 0x0002;
	const SSLv3  = 0x0300;
	const TLSv10 = 0x0301;
	const TLSv11 = 0x0302;
	const version_strings: table[count] of string = {
		[SSLv2] = "SSLv2",
		[SSLv3] = "SSLv3",
		[TLSv10] = "TLSv10",
		[TLSv11] = "TLSv11",
	} &default="UNKNOWN";
	
}

# NOTE: this is a 'local' port format for your site
# --- well-known ports for ssl ---------
redef capture_filters += {
	["ssl"] = "tcp port 443",
	["nntps"] = "tcp port 563",
	["imap4-ssl"] = "tcp port 585",
	["sshell"] = "tcp port 614",
	["ldaps"] = "tcp port 636",
	["ftps-data"] = "tcp port 989",
	["ftps"] = "tcp port 990",
	["telnets"] = "tcp port 992",
	["imaps"] = "tcp port 993",
	["ircs"] = "tcp port 994",
	["pop3s"] = "tcp port 995"
};

global ssl_ports = {
	443/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
	989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp,
};

redef dpd_config += {
	[[ANALYZER_SSL, ANALYZER_SSL_BINPAC]] = [$ports = ssl_ports]
};

event bro_init()
	{
	Log::create_stream(SSL, [$columns=SSL::Log, $ev=log_ssl] );
	Log::add_default_filter(SSL);
	
	# The event engine will generate a run-time if this fails for
	# reasons other than that the directory already exists.
	if ( ssl_store_cert_path != "" )
		mkdir(ssl_store_cert_path);
    }

const x509_ignore_errors: set[int] = {
	X509_V_OK,
	# X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
};

const x509_hot_errors: set[int] = {
	X509_V_ERR_CRL_SIGNATURE_FAILURE,
	X509_V_ERR_CERT_NOT_YET_VALID,
	X509_V_ERR_CERT_HAS_EXPIRED,
	X509_V_ERR_CERT_REVOKED,
	X509_V_ERR_SUBJECT_ISSUER_MISMATCH,
	# X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE	# for testing
};

@ifdef ( Weird::weird_file )
	redef Weird::weird_action += {
		[["SSLv2: Unknown CIPHER-SPEC in CLIENT-HELLO!",
		  "SSLv2: Client has CipherSpecs > MAX_CIPHERSPEC_SIZE",
		  "unexpected_SSLv3_record",
		  "SSLv3_data_without_full_handshake"]]	= Weird::WEIRD_IGNORE
	};
@endif

function ssl_get_cipher_name(cipherSuite: count): string
	{
	return cipherSuite in ssl_cipher_desc ?
		ssl_cipher_desc[cipherSuite] : "UNKNOWN";
	}
	
function get_connection_info(c: connection): ConnectionInfo
	{
	local id = c$id;
	
	if ( id in active_conns )
		return active_conns[id];
	else
		{
		local log: Log = [$ts=network_time(), $id=id];
		local conn_info: ConnectionInfo = [$log=log];
		active_conns[id] = conn_info;
		return conn_info;
		}
	}
	
function get_session_info(s: SSL_sessionID): SessionInfo
	{
	local sess_info: SessionInfo;

	local index = md5_hash(s);
	recent_sessions[index] = sess_info;
	return sess_info;
	}

event ssl_certificate(c: connection, cert: X509, is_server: bool)
	{
	#if ( is_server )
	#	event protocol_confirmation(c, ANALYZER_SSL, 0);
	local conn = get_connection_info(c);

	if ( [c$id$resp_h, c$id$resp_p, cert$subject] !in certs )
		add certs[c$id$resp_h, c$id$resp_p, cert$subject];

	if( is_server )
		{
		conn$log$server_cert = cert;

		# We have not filled in the field for the master session
		# for this connection.  Do it now, but only if this is not a
		# SSLv2 connection (no session information in that case).
		if ( conn$log$sid in recent_sessions &&
		     recent_sessions[conn$log$sid]?$server_cert )
			recent_sessions[conn$log$sid]$server_cert$subject = cert$subject;
		}
	else
		{
		conn$log$client_cert = cert;
		}
	}

event ssl_conn_attempt(c: connection, version: count, ciphers: cipher_suites_list)
	{
	local conn = get_connection_info(c);
	
	conn$log$version = version_strings[version];
	
	for ( cs in ciphers )
		{
		if ( cs in weak_ciphers )
			{
			conn$log$weak_client_cipher = T;
			#event ssl_conn_weak(
			#	fmt("SSL client supports weak cipher: %s (0x%x)",
			#		ssl_get_cipher_name(cs), cs), c);
			}
		}
	}

event ssl_conn_server_reply(c: connection, version: count,
				ciphers: cipher_suites_list)
	{
	local conn = get_connection_info(c);
	
	#conn$log$version = version_strings[version];

	for ( cs in ciphers )
		{
		if ( cs in weak_ciphers )
			{
			conn$log$weak_server_cipher = T;
			#event ssl_conn_weak(
			#	fmt("SSLv2 server supports weak cipher: %s (0x%x)",
			#		ssl_get_cipher_name(cs), cs), c);
			}
		}
	}

event ssl_conn_established(c: connection, version: count, cipher_suite: count) &priority=1
	{
	local conn = get_connection_info(c);
	
	conn$log$ts = network_time();
	#conn$log$version = version_strings[version];
	
	if ( cipher_suite in weak_ciphers )
		conn$log$weak_cipher_agreed = T;
	
	# log the connection
	Log::write(SSL, conn$log);
	}

event process_X509_extensions(c: connection, ex: X509_extension)
	{
	local conn = get_connection_info(c);

	#local msg = fmt( "%.6f X.509 extensions: ", network_time() );
	#for ( i in ex )
	#	msg = fmt("%s, %s", msg, ex[i]);
	}

event ssl_session_insertion(c: connection, id: SSL_sessionID)
	{
	local cid = c$id;
	local conn = get_connection_info(c);
	conn$log$sid=md5_hash(id);
	
	# This will create a new session if one doesn't already exist.
	local session = get_session_info(id);
	session$version=conn$log$version;
	if ( conn$log?$client_cert ) session$client_cert=conn$log$client_cert;
	if ( conn$log?$server_cert ) session$server_cert=conn$log$server_cert;
	session$handshake_cipher=conn$log$handshake_cipher;
	}

event ssl_conn_reused(c: connection, session_id: SSL_sessionID)
	{
	local conn = get_connection_info(c);

	# We cannot track sessions with SSLv2.
	if ( conn$log$version == version_strings[SSLv2] )
		return;

	local session = get_session_info(session_id);
	++session$num_reuse;

	# At this point, the connection values have been set.  We can then
	# compare session and connection values with some confidence.
	if ( session$version != conn$log$version ||
	     session$handshake_cipher != conn$log$handshake_cipher )
		{
		NOTICE([$note=SSL_SessConIncon, $conn=c, $msg="session violation"]);
		}
	}

event ssl_X509_error(c: connection, err: int, err_string: string)
	{
	if ( err in x509_ignore_errors )
		return;

	local conn = get_connection_info(c);
	local error =
		err in x509_errors ?  x509_errors[err] : "unknown X.509 error";

	local severity = "warning";
	if ( err in x509_hot_errors )
		{
		NOTICE([$note=SSL_X509Violation, $conn=c, $msg=error]);
		++c$hot;
		severity = "error";
		}
	}

event connection_state_remove(c: connection)
	{
	delete active_conns[c$id];
	}

