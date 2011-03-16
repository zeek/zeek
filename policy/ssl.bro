# $Id: ssl.bro 5988 2008-07-19 07:02:12Z vern $

@load notice
@load conn
@load weird
@load ssl-ciphers
@load ssl-errors
@load functions

module SSL;

export {
	redef enum Log::ID += { SSL_SERVER };
    type ServerLog: record {
        ts:                             time;       # timestamp
        client_address:                 addr;       # client address
        client_port:                    port;       # client port
        cert_subject:                   X509;       # certificate subject
        not_valid_before:               time;       # certificate valid time constraint
        not_valid_after:                time;       # certificate valid time constraint
        ssl_tls_version:                string;     # version number
        weak_client_ciphers_offered:    bool;       # true if client offered insecure ciphers
        weak_server_ciphers_offered:    bool;       # true if server offered insecure ciphers
        weak_cipher_agreed:             bool;       # true if insecure cipher agreed upon for use
    };


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

    # Report weak/unknown ciphers in CLIENT_HELLO, SSLv2 SERVER_HELLO.
    const ssl_report_client_weak = F &redef;
    const ssl_report_client_unknown = F &redef;
    const ssl_report_server_weak = F &redef;

    # Log all ciphers.
# TODO: dga 3/11 Discarded for now; could be re-added, perhaps as a separate stream for the curious
#    const ssl_log_ciphers = T &redef;

    global ssl_ports = {
        443/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
        989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp,
    } &redef;
}

event bro_init()
    {
    Log::create_stream( "SSL_SERVER", "SSL::ServerLog" );
    Log::add_default_filter( "SSL_SERVER" );
    }


redef enum Notice += {
	SSL_X509Violation,	# blanket X509 error
	SSL_SessConIncon,	# session data not consistent with connection
};

const SSLv2  = 0x0002;
const SSLv3  = 0x0300;
const TLSv10 = 0x0301;
const TLSv11 = 0x0302;

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

redef Weird::weird_action += {
	[["SSLv2: Unknown CIPHER-SPEC in CLIENT-HELLO!",
	  "SSLv2: Client has CipherSpecs > MAX_CIPHERSPEC_SIZE",
	  "unexpected_SSLv3_record",
	  "SSLv3_data_without_full_handshake"]]	= Weird::WEIRD_IGNORE
};

global SSL_cipherCount: table[count] of count &default = 0;

# track weak ciphers offered by client and/or server until it can be logged
global ssl_weak_client_ciphers: table[conn_id] of bool &read_expire = 2 hrs;
global ssl_weak_server_ciphers: table[conn_id] of bool &read_expire = 2 hrs;


type ssl_connection_info: record {
	id:                 count;		# the log identifier number
	connection_id:      conn_id;	# IP connection information
	version:            string;		# version associated with connection
	client_cert:        X509;
	server_cert:        X509;
	id_index:           string;		# index for associated SSL_sessionID
	handshake_cipher:   string;	    # agreed-upon cipher for session/conn.
};

# SSL_sessionID index - used to track version associated with a session id.
type SSL_sessionID_record: record {
	num_reuse:          count;
	id:                 SSL_sessionID;	# literal session ID

	# everything below is an example of session vs connection monitoring.
	version:            string;	# version assosciated with session id
	client_cert:        X509;
	server_cert:        X509;
	handshake_cipher:   string;
};

global ssl_connections: table[conn_id] of ssl_connection_info;
global ssl_sessionIDs: table[string] of SSL_sessionID_record
						&read_expire = 2 hrs;
global ssl_connection_id = 0;

# Used when there's no issuer/subject/cipher.
const NONE = "<none>";

# --- SSL helper functions ---------
function new_ssl_connection(c: connection)
	{
	local conn = c$id;
	local new_id = ++ssl_connection_id;

	local info: ssl_connection_info;
	info$id = new_id;
	info$id_index = md5_hash(info$id);
	info$version = "";
	info$client_cert$issuer = NONE;
	info$client_cert$subject = NONE;
	info$server_cert$issuer = NONE;
	info$server_cert$subject = NONE;
	info$handshake_cipher = NONE;
	info$connection_id = conn;

	ssl_connections[conn] = info;
	append_addl( c, fmt( "#%d", new_id ) );
	}

function new_sessionID_record(session: SSL_sessionID)
	{
	local info: SSL_sessionID_record;

	info$num_reuse = 1;
	info$client_cert$issuer = NONE;
	info$client_cert$subject = NONE;
	info$server_cert$issuer = NONE;
	info$server_cert$subject = NONE;
	info$handshake_cipher = NONE;

	local index = md5_hash(session);
	ssl_sessionIDs[index] = info;
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

function ssl_con2str(c: connection): string
	{
	return fmt("%s:%s -> %s:%s",
			c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
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
	local direction = is_local_addr(c$id$orig_h) ? "client" : "server";

	lookup_ssl_conn(c, "ssl_certificate", T);
	local conn = ssl_connections[c$id];

	if( direction == "client" )
		conn$client_cert = cert;
	else
		{
		conn$server_cert = cert;

		# We have not filled in the field for the master session
		# for this connection.  Do it now, but only if this is not a
		# SSLv2 connection (no session information in that case).
		if ( conn$id_index in ssl_sessionIDs &&
		     ssl_sessionIDs[conn$id_index]$server_cert$subject == NONE )
			ssl_sessionIDs[conn$id_index]$server_cert$subject =
				cert$subject;
		}
	}

event ssl_conn_attempt(c: connection, version: count,
			ciphers: cipher_suites_list)
	{
	lookup_ssl_conn(c, "ssl_conn_attempt", F);
	local conn = ssl_connections[c$id];
	local version_string = ssl_get_version_string(version);

	conn$version = version_string;

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

    ssl_weak_client_ciphers[ c$id ] = has_weak_ciphers;
	}

event ssl_conn_server_reply(c: connection, version: count,
				ciphers: cipher_suites_list)
	{
	lookup_ssl_conn(c, "ssl_conn_server_reply", T);

	local conn = ssl_connections[c$id];
	local version_string = ssl_get_version_string(version);

#	print ssl_log, fmt("%.6f #%d SSL connection server reply, %s",
#				network_time(), conn$id, version_string);

	conn$version = version_string;

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

    ssl_weak_server_ciphers[ c$id ] = has_weak_ciphers;
	}

event ssl_conn_established(c: connection, version: count, cipher_suite: count)
	{
	lookup_ssl_conn(c, "ssl_conn_established", T);

	local conn = ssl_connections[c$id];
	local version_string = ssl_get_version_string(version);

    local has_weak_ciphers = F;
	if ( cipher_suite in myWeakCiphers )
        {
        has_weak_ciphers = T;
		event ssl_conn_weak(fmt("%.6f #%d weak cipher: %s (0x%x)",
			network_time(), conn$id,
			ssl_get_cipher_name(cipher_suite), cipher_suite), c);
        }

	++SSL_cipherCount[cipher_suite];

	# This should be the version identified with the session, unless
	# there is some renegotiation.  That will be caught later.
	conn$version = version_string;

    # log the connection
    Log::write( "SSL_SERVER", [ $ts = network_time(),
                                $client_address = c$id$orig_h,
                                $client_port = c$id$orig_p,
                                $cert_subject = conn$client_cert$subject,
                                # TODO: dga 3/11 The following are not yet picked up
#                                $not_valid_before = ???,
#                                $not_valid_after = ???,
#                                $ssl_tls_version = ???,
                                $weak_client_ciphers_offered = ssl_weak_client_ciphers[ c$id ],
                                $weak_server_ciphers_offered = ssl_weak_server_ciphers[ c$id ],
                                $weak_cipher_agreed = has_weak_ciphers
                                ] );
	}

event process_X509_extensions(c: connection, ex: X509_extension)
	{
	lookup_ssl_conn(c, "process_X509_extensions", T);
	local conn = ssl_connections[c$id];

	local msg = fmt("%.6f #%d X.509 extensions: ", network_time(), conn$id);
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

	# If there is no session with thIS id we create (a typical) one,
	# otherwise we move on.
	if ( id_index !in ssl_sessionIDs )
		{
		new_sessionID_record(id);

		local session = ssl_sessionIDs[id_index];
		session$version = conn$version;
		session$client_cert$subject = conn$client_cert$subject;
		session$server_cert$subject = conn$server_cert$subject;
		session$handshake_cipher = conn$handshake_cipher;
		session$id = id;

		conn$id_index = id_index;
		}

	else
		{ # should we ever get here?
		session = ssl_sessionIDs[id_index];
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

	if ( id_index !in ssl_sessionIDs )
		{
		new_sessionID_record(session_id);
		local session = ssl_sessionIDs[id_index];
		session$version = conn$version;
		session$client_cert$subject = conn$client_cert$subject;
		session$server_cert$subject = conn$server_cert$subject;
		session$id = session_id;
		}
	else
		session = ssl_sessionIDs[id_index];

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

event bro_init()
	{
	if ( ssl_store_cert_path != "" )
		# The event engine will generate a run-time if this fails for
		# reasons other than that the directory already exists.
		mkdir(ssl_store_cert_path);
	}

event bro_done()
	{
	# TODO: Do we want this end-of-run logging back?
#	print ssl_log, "Cipher suite statistics: ";
#	for ( i in SSL_cipherCount )
#		print ssl_log, fmt("%s (0x%x): %d", ssl_get_cipher_name(i), i,
#					SSL_cipherCount[i]);
#
#	print ssl_log, ("count     session ID");
#	print ssl_log, ("-----     ---------------------------------");
#	for ( j in ssl_sessionIDs )
#		if ( ssl_sessionIDs[j]$server_cert$subject != NONE )
#			{
#			print ssl_log,
#				fmt("(%s)      %s   %s",
#					ssl_sessionIDs[j]$num_reuse,
#					ssl_sessionIDs[j]$server_cert$subject,
#					j);
#			}
	}
