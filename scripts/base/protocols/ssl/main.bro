##! Base SSL analysis script.  This script logs information about the SSL/TLS
##! handshaking and encryption establishment process.

@load ./consts

module SSL;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time when the SSL connection was first detected.
		ts:               time             &log;
		## Unique ID for the connection.
		uid:         string          &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id          &log;
		## SSL/TLS version that the server offered.
		version:          string           &log &optional;
		## SSL/TLS cipher suite that the server chose.
		cipher:           string           &log &optional;
		## Value of the Server Name Indicator SSL/TLS extension.  It
		## indicates the server name that the client was requesting.
		server_name:      string           &log &optional;
		## Session ID offered by the client for session resumption.
		session_id:       string           &log &optional;
		## Subject of the X.509 certificate offered by the server.
		subject:          string           &log &optional;
		## Subject of the signer of the X.509 certificate offered by the server.
		issuer_subject:   string           &log &optional;
		## NotValidBefore field value from the server certificate.
		not_valid_before: time             &log &optional;
		## NotValidAfter field value from the server certificate.
		not_valid_after:  time             &log &optional;
		## Last alert that was seen during the connection.
		last_alert:       string           &log &optional;

		## Subject of the X.509 certificate offered by the client.
		client_subject:          string           &log &optional;
		## Subject of the signer of the X.509 certificate offered by the client.
		client_issuer_subject:   string           &log &optional;

		## Full binary server certificate stored in DER format.
		cert:             string           &optional;
		## Chain of certificates offered by the server to validate its
		## complete signing chain.
		cert_chain:       vector of string &optional;

		## Full binary client certificate stored in DER format.
		client_cert:             string           &optional;
		## Chain of certificates offered by the client to validate its
		## complete signing chain.
		client_cert_chain:       vector of string &optional;

		## The analyzer ID used for the analyzer instance attached
		## to each connection.  It is not used for logging since it's a
		## meaningless arbitrary number.
		analyzer_id:      count            &optional;
	};

	## The default root CA bundle.  By loading the
	## mozilla-ca-list.bro script it will be set to Mozilla's root CA list.
	const root_certs: table[string] of string = {} &redef;

	## If true, detach the SSL analyzer from the connection to prevent
	## continuing to process encrypted traffic. Helps with performance
	## (especially with large file transfers).
	const disable_analyzer_after_detection = T &redef;

	## The openssl command line utility.  If it's in the path the default
	## value will work, otherwise a full path string can be supplied for the
	## utility.
	const openssl_util = "openssl" &redef;

	## The maximum amount of time a script can delay records from being logged.
	const max_log_delay = 15secs &redef;

	## Delays an SSL record for a specific token: the record will not be logged
	## as longs the token exists or until :bro:id:`SSL::max_log_delay` elapses.
	global delay_log: function(info: Info, token: string);

	## Undelays an SSL record for a previously inserted token, allowing the
	## record to be logged.
	global undelay_log: function(info: Info, token: string);

	## Event that can be handled to access the SSL
	## record as it is sent on to the logging framework.
	global log_ssl: event(rec: Info);
}

redef record connection += {
	ssl: Info &optional;
};

redef record Info += {
		# Adding a string "token" to this set will cause the SSL script
		# to delay logging the record until either the token has been removed or
		# the record has been delayed for :bro:id:`SSL::max_log_delay`.
		delay_tokens: set[string] &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(SSL::LOG, [$columns=Info, $ev=log_ssl]);
	}

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
	["pop3s"] = "tcp port 995",
	["xmpps"] = "tcp port 5223",
};

const ports = {
	443/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
	989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp, 5223/tcp
};

redef dpd_config += {
	[[ANALYZER_SSL]] = [$ports = ports]
};

redef likely_server_ports += {
	443/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
	989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp, 5223/tcp
};

# A queue that buffers log records.
global log_delay_queue: table[count] of Info;
# The top queue index where records are added.
global log_delay_queue_head = 0;
# The bottom queue index that points to the next record to be flushed.
global log_delay_queue_tail = 0;

function set_session(c: connection)
	{
	if ( ! c?$ssl )
		c$ssl = [$ts=network_time(), $uid=c$uid, $id=c$id, $cert_chain=vector(),
		         $client_cert_chain=vector()];
	}

function delay_log(info: Info, token: string)
	{
	info$delay_tokens = set();
	add info$delay_tokens[token];

	log_delay_queue[log_delay_queue_head] = info;
	++log_delay_queue_head;
	}

function undelay_log(info: Info, token: string)
	{
	if ( token in info$delay_tokens )
		delete info$delay_tokens[token];
	}

global log_record: function(info: Info);

event delay_logging(info: Info)
	{
	log_record(info);
	}

function log_record(info: Info)
	{
	if ( ! info?$delay_tokens || |info$delay_tokens| == 0 )
		{
		Log::write(SSL::LOG, info);
		}
	else
		{
		for ( unused_index in log_delay_queue )
			{
			if ( log_delay_queue_head == log_delay_queue_tail )
				return;
			if ( |log_delay_queue[log_delay_queue_tail]$delay_tokens| > 0 )
				{
				if ( info$ts + max_log_delay > network_time() )
					{
					schedule 1sec { delay_logging(info) };
					return;
					}
				else
					{
					Reporter::info(fmt("SSL delay tokens not released in time (%s)",
					                   info$delay_tokens));
					}
				}
			Log::write(SSL::LOG, log_delay_queue[log_delay_queue_tail]);
			delete log_delay_queue[log_delay_queue_tail];
			++log_delay_queue_tail;
			}
		}
	}

function finish(c: connection)
	{
	log_record(c$ssl);
	if ( disable_analyzer_after_detection && c?$ssl && c$ssl?$analyzer_id )
		disable_analyzer(c$id, c$ssl$analyzer_id);
	}

event ssl_client_hello(c: connection, version: count, possible_ts: time, session_id: string, ciphers: count_set) &priority=5
	{
	set_session(c);

	# Save the session_id if there is one set.
	if ( session_id != /^\x00{32}$/ )
		c$ssl$session_id = bytestring_to_hexstr(session_id);
	}

event ssl_server_hello(c: connection, version: count, possible_ts: time, session_id: string, cipher: count, comp_method: count) &priority=5
	{
	set_session(c);

	c$ssl$version = version_strings[version];
	c$ssl$cipher = cipher_desc[cipher];
	}

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string) &priority=5
	{
	set_session(c);

	# We aren't doing anything with client certificates yet.
	if ( is_orig )
		{
		if ( chain_idx == 0 )
			{
			# Save the primary cert.
			c$ssl$client_cert = der_cert;

			# Also save other certificate information about the primary cert.
			c$ssl$client_subject = cert$subject;
			c$ssl$client_issuer_subject = cert$issuer;
			}
		else
			{
			# Otherwise, add it to the cert validation chain.
			c$ssl$client_cert_chain[|c$ssl$client_cert_chain|] = der_cert;
			}
		}
	else
		{
		if ( chain_idx == 0 )
			{
			# Save the primary cert.
			c$ssl$cert = der_cert;

			# Also save other certificate information about the primary cert.
			c$ssl$subject = cert$subject;
			c$ssl$issuer_subject = cert$issuer;
			c$ssl$not_valid_before = cert$not_valid_before;
			c$ssl$not_valid_after = cert$not_valid_after;
			}
		else
			{
			# Otherwise, add it to the cert validation chain.
			c$ssl$cert_chain[|c$ssl$cert_chain|] = der_cert;
			}
		}
	}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string) &priority=5
	{
	set_session(c);

	if ( is_orig && extensions[code] == "server_name" )
		c$ssl$server_name = sub_bytes(val, 6, |val|);
	}

event ssl_alert(c: connection, is_orig: bool, level: count, desc: count) &priority=5
	{
	set_session(c);

	c$ssl$last_alert = alert_descriptions[desc];
	}

event ssl_established(c: connection) &priority=5
	{
	set_session(c);
	}

event ssl_established(c: connection) &priority=-5
	{
	finish(c);
	}

event protocol_confirmation(c: connection, atype: count, aid: count) &priority=5
	{
	# Check by checking for existence of c$ssl record.
	if ( c?$ssl && analyzer_name(atype) == "SSL" )
		c$ssl$analyzer_id = aid;
	}

event protocol_violation(c: connection, atype: count, aid: count,
                         reason: string) &priority=5
	{
	if ( c?$ssl )
		finish(c);
	}

event bro_done()
	{
	if ( |log_delay_queue| == 0 )
		return;
	for ( unused_index in log_delay_queue )
		{
		Log::write(SSL::LOG, log_delay_queue[log_delay_queue_tail]);
		delete log_delay_queue[log_delay_queue_tail];
		++log_delay_queue_tail;
		}
	}
