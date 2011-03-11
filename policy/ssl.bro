# $Id: ssl.bro 5988 2008-07-19 07:02:12Z vern $

##! SSL connections

@load functions
@load notice

@load ssl-ciphers
@load ssl-errors


module SSL;

redef enum Notice::Type += {
	SSL_X509Violation,	# blanket X509 error
	SSL_SessConIncon,	# session data not consistent with connection
};


export {
	############## logging ################

	redef enum Log::ID += { SSL };
    type Log: record {
        ts:                             time;       # timestamp
		# TODO: dga 3/11 The following 2 fields are not yet picked up
        not_valid_before:               time;       # certificate valid time constraint
        not_valid_after:                time;       # certificate valid time constraint
        ssl_tls_version:                string;     # version number
        weak_client_ciphers_offered:    bool &default = F;  # true if client offered insecure ciphers
        weak_server_ciphers_offered:    bool &default = F;  # true if server offered insecure ciphers
        weak_cipher_agreed:             bool &default = F;  # true if insecure cipher agreed upon for use

		connection_id:      conn_id;	# IP connection information
		id_index:           string;		# index for associated SSL_sessionID
		version:            string;		# version associated with connection
		client_cert:        X509;       # client certificate
		server_cert:        X509;       # server certificate
		handshake_cipher:   string;	    # agreed-upon cipher for session/conn.
    };

	############### types #################

	# SSL_sessionID index - used to track version associated with a session id.
	type SSLSessionIDRecord: record {
		num_reuse:          count;
		id:                 SSL_sessionID;	# literal session ID

		# everything below is an example of session vs connection monitoring.
		version:            string;	# version associated with session id
		client_cert:        X509;
		server_cert:        X509;
		handshake_cipher:   string;
	};

	############## options ################

	# Certificates presented by which hosts to record.
	# Choices are: LocalHosts, RemoteHosts, Enabled, Disabled
	const logging = LocalHosts &redef;

	# If set to T, this will split local and remote certs
	# into separate files.  F merges everything into a single file.
	const split_log_file = F &redef;

    # If true, Bro stores the client and server cipher specs and performs
    # additional tests.  This costs an extra amount of memory (normally
    # only for a short time) but enables detecting of non-intersecting
    # cipher sets, for example.
# TODO: dga 3/11 Unused, discarded for now; could be re-added
#    const ssl_compare_cipherspecs = T &redef;

    # Whether to analyze certificates seen in SSL connections.
# TODO: dga 3/11 Unused, discarded for now; could be re-added
#    const ssl_analyze_certificates = T &redef;

    # If we analyze SSL certificates, we can choose to store them.
# TODO: dga 3/11 Unused, discarded for now; could be re-added in event ssl_certificate_seen()
#    const ssl_store_certificates = T &redef;

    # Path where we dump the certificates into.  If it's empty,
    # use the current directory.
# TODO: dga 3/11 Unused, discarded for now; could be re-added; disabled mkdir in bro_init() handler
#    const ssl_store_cert_path = "certs" &redef;

    # If we analyze SSL certificates, we can choose to verify them.
# TODO: dga 3/11 Unused, discarded for now; could be re-added in event ssl_certificate_seen()
#    const ssl_verify_certificates = T &redef;

    # This is the path where OpenSSL looks after the trusted certificates.
    # If empty, the default path will be used.
# TODO: dga 3/11 Unused, discarded for now; could be re-added
#    const x509_trusted_cert_path = "" &redef;

    # Whether to store key-material exchanged in the handshaking phase.
# TODO: dga 3/11 Unused, discarded for now; could be re-added
#    const ssl_store_key_material = F &redef;

    # Report weak/unknown ciphers in CLIENT_HELLO, SSLv2 SERVER_HELLO.
    const ssl_report_client_weak = F &redef;        # TODO: dga 3/11 Unused
    const ssl_report_client_unknown = F &redef;
    const ssl_report_server_weak = F &redef;

    # Log all ciphers.
# TODO: dga 3/11 Discarded for now; could be re-added, perhaps as a separate stream for the curious
#    const ssl_log_ciphers = T &redef;

    global ssl_ports = {
        443/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
        989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp,
    } &redef;

	############## state variables ############

	# table of ssl connections
	global ssl_connections: table[conn_id] of Log;

	# The list of all detected certs.  This prevents over-logging.
	global certs: set[addr, port, string] &create_expire=1day &synchronized;

	global ssl_session_ids: table[string] of SSLSessionIDRecord
							&read_expire = 2 hrs;
	global ssl_connection_id = 0;
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

redef dpd_config += {
	[[ANALYZER_SSL, ANALYZER_SSL_BINPAC]] = [$ports = ssl_ports]
};


event bro_init()
    {
    Log::create_stream( "SSL", "SSL::Log" );
    Log::add_default_filter( "SSL" );

#	if ( ssl_store_cert_path != "" )
#		# The event engine will generate a run-time if this fails for
#		# reasons other than that the directory already exists.
#		mkdir(ssl_store_cert_path);
    }


const SSLv2  = 0x0002;
const SSLv3  = 0x0300;
const TLSv10 = 0x0301;
const TLSv11 = 0x0302;

# --- Weak Cipher Demo -------------

const myWeakCiphers: set[count] = {
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
};

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

# Used when there's no issuer/subject/cipher.
const NONE = "<none>";

# --- SSL helper functions ---------
function new_ssl_connection(c: connection)
	{
	local conn = c$id;
	local new_id = ++ssl_connection_id;

	local log_entry: Log;
	log_entry$id_index = md5_hash( new_id );
	log_entry$version = "";
	log_entry$client_cert$issuer = NONE;
	log_entry$client_cert$subject = NONE;
	log_entry$server_cert$issuer = NONE;
	log_entry$server_cert$subject = NONE;
	log_entry$handshake_cipher = NONE;
	log_entry$connection_id = conn;

	ssl_connections[conn] = log_entry;
	append_addl( c, fmt( "#%d", new_id ) );
	}

function new_sessionID_record(session: SSL_sessionID)
	{
	local info: SSLSessionIDRecord;

	info$num_reuse = 1;
	info$client_cert$issuer = NONE;
	info$client_cert$subject = NONE;
	info$server_cert$issuer = NONE;
	info$server_cert$subject = NONE;
	info$handshake_cipher = NONE;

	local index = md5_hash(session);
	ssl_session_ids[index] = info;
	}

function ssl_get_cipher_name(cipherSuite: count): string
	{
	return cipherSuite in ssl_cipher_desc ?
		ssl_cipher_desc[cipherSuite] : "UNKNOWN";
	}

function ssl_get_version_string(version: count): string
	{
	if ( version == SSLv2 )
		return "SSL version 2";
	else if ( version == SSLv3 )
		return "SSL version 3";
	else if ( version == TLSv10 )
		return "TLS version 1.0";
	else if ( version == TLSv11 )
		return "TLS version 1.1";
	else
		return "?.?";
	}

function lookup_ssl_conn(c: connection, func: string, log_if_new: bool)
	{
	if ( c$id !in ssl_connections )
		new_ssl_connection(c);
	}

event ssl_conn_weak(name: string, c: connection)
	{
	lookup_ssl_conn(c, "ssl_conn_weak", T);
	}

# --- SSL events -------------------

event ssl_certificate_seen(c: connection, is_server: bool)
	{
	# Called whenever there's a certificate to analyze.
	# we could do something here, like...

	# if ( c$id$orig_h in hostsToIgnore )
	#	{
	#	ssl_store_certificates = F;
	#	ssl_verify_certificates = F;
	#	}
	# else
	#	{
	#	ssl_store_certificates = T;
	#	ssl_verify_certificates = T;
	#	}
	}

event ssl_certificate(c: connection, cert: X509, is_server: bool)
	{
	if ( is_server )
		event protocol_confirmation(c, ANALYZER_SSL, 0);

	lookup_ssl_conn(c, "ssl_certificate", T);
	local conn = ssl_connections[c$id];

	if ( [c$id$resp_h, c$id$resp_p, cert$subject] !in certs )
		add certs[c$id$resp_h, c$id$resp_p, cert$subject];

	if( is_server )
		{
		conn$server_cert = cert;

		# We have not filled in the field for the master session
		# for this connection.  Do it now, but only if this is not a
		# SSLv2 connection (no session information in that case).
		if ( conn$id_index in ssl_session_ids &&
		     ssl_session_ids[conn$id_index]$server_cert$subject == NONE )
			ssl_session_ids[conn$id_index]$server_cert$subject =
				cert$subject;
		}
	else
		conn$client_cert = cert;
	}

event ssl_conn_attempt(c: connection, version: count,
			ciphers: cipher_suites_list)
	{
	lookup_ssl_conn(c, "ssl_conn_attempt", F);
	local log_entry = ssl_connections[c$id];
	local version_string = ssl_get_version_string(version);

	log_entry$version = version_string;

    local has_weak_ciphers = F;
	for ( cs in ciphers )
		{ # display a list of the cipher suites
		# Demo: report clients who support weak ciphers.
		if ( cs in myWeakCiphers )
		    {
		    has_weak_ciphers = T;
			event ssl_conn_weak(
				fmt("SSL client supports weak cipher: %s (0x%x)",
					ssl_get_cipher_name(cs), cs), c);
            }

		# Demo: report unknown ciphers.
		if ( ssl_report_client_unknown && cs !in ssl_cipher_desc )
			event ssl_conn_weak(
				fmt("SSL: unknown cipher-spec: %s (0x%x)",
					ssl_get_cipher_name(cs), cs), c);
		}

	log_entry$weak_client_ciphers_offered = has_weak_ciphers;
	}

event ssl_conn_server_reply(c: connection, version: count,
				ciphers: cipher_suites_list)
	{
	lookup_ssl_conn(c, "ssl_conn_server_reply", T);

	local log_entry = ssl_connections[c$id];
	local version_string = ssl_get_version_string(version);

	log_entry$version = version_string;

    local has_weak_ciphers = F;
	for ( cs in ciphers )
		{
		# Demo: report servers who support weak ciphers.
		if ( ssl_report_server_weak && version == SSLv2 &&
		     cs in myWeakCiphers )
		    {
		    has_weak_ciphers = T;
			event ssl_conn_weak(
				fmt("SSLv2 server supports weak cipher: %s (0x%x)",
					ssl_get_cipher_name(cs), cs), c);
            }
		}

    log_entry$weak_server_ciphers_offered = has_weak_ciphers;
	}

event ssl_conn_established(c: connection, version: count, cipher_suite: count)
	{
	lookup_ssl_conn(c, "ssl_conn_established", T);

	local log_entry = ssl_connections[c$id];
	local version_string = ssl_get_version_string(version);

    local has_weak_ciphers = F;
	if ( cipher_suite in myWeakCiphers )
        {
        has_weak_ciphers = T;
		event ssl_conn_weak(fmt("%.6f weak cipher: %s (0x%x)",
			network_time(),
			ssl_get_cipher_name(cipher_suite), cipher_suite), c);
        }

	# Set a few more values in the log entry
	log_entry$ts = network_time();
	log_entry$weak_cipher_agreed = has_weak_ciphers;

	# This should be the version identified with the session, unless
	# there is some renegotiation.  That will be caught later.
	log_entry$version = version_string;

    # log the connection
    Log::write( "SSL", log_entry );
	}

event process_X509_extensions(c: connection, ex: X509_extension)
	{
	lookup_ssl_conn(c, "process_X509_extensions", T);
	local conn = ssl_connections[c$id];

	local msg = fmt( "%.6f X.509 extensions: ", network_time() );
	for ( i in ex )
		msg = fmt("%s, %s", msg, ex[i]);
	}

event ssl_session_insertion(c: connection, id: SSL_sessionID)
	{
	local idd = c$id;

	if ( idd !in ssl_connections)
		{
		new_ssl_connection(c);

		# None of the conn$object values will exist, so we leave this
		# to prevent needless crashing.
		return;
		}

	local conn = ssl_connections[idd];
	local id_index = md5_hash(id);

	# If there is no session with this id we create (a typical) one,
	# otherwise we move on.
	if ( id_index !in ssl_session_ids )
		{
		new_sessionID_record(id);

		local session = ssl_session_ids[id_index];
		session$version = conn$version;
		session$client_cert$subject = conn$client_cert$subject;
		session$server_cert$subject = conn$server_cert$subject;
		session$handshake_cipher = conn$handshake_cipher;
		session$id = id;

		conn$id_index = id_index;
		}

	else
		{ # should we ever get here?
		session = ssl_session_ids[id_index];
		conn$id_index = id_index;
		}
	}

event ssl_conn_reused(c: connection, session_id: SSL_sessionID)
	{
	lookup_ssl_conn(c, "ssl_conn_reused", T);
	local conn = ssl_connections[c$id];
	local id_index = md5_hash(session_id);

	# We cannot track sessions with SSLv2.
	if ( conn$version == ssl_get_version_string(SSLv2) )
		return;

	if ( id_index !in ssl_session_ids )
		{
		new_sessionID_record(session_id);
		local session = ssl_session_ids[id_index];
		session$version = conn$version;
		session$client_cert$subject = conn$client_cert$subject;
		session$server_cert$subject = conn$server_cert$subject;
		session$id = session_id;
		}
	else
		session = ssl_session_ids[id_index];

	++session$num_reuse;

	# At this point, the connection values have been set.  We can then
	# compare session and connection values with some confidence.
	if ( session$version != conn$version ||
	     session$handshake_cipher != conn$handshake_cipher )
		{
		NOTICE([$note=SSL_SessConIncon, $conn=c,
			$msg="session violation"]);
		++c$hot;
		}
	}

event ssl_X509_error(c: connection, err: int, err_string: string)
	{
	if ( err in x509_ignore_errors )
		return;

	lookup_ssl_conn(c, "ssl_X509_error", T);
	local conn = ssl_connections[c$id];
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
	delete ssl_connections[c$id];
	}

