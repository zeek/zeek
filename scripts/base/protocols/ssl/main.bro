##! Base SSL analysis script.  This script logs information about the SSL/TLS
##! handshaking and encryption establishment process.

@load ./consts

module SSL;

export {
	redef enum Log::ID += { LOG };

	## A response from the ICSI certificate notary.
	type NotaryResponse: record {
		first_seen: count &log &optional;
		last_seen: count &log &optional;
		times_seen: count &log &optional;
		valid: bool &log &optional;
	};

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

	## Flag that determines whether to use the ICSI certificate notary to enhance
	## the SSL log records.
	const use_notary = T &redef;

	## Event that can be handled to access the SSL
	## record as it is sent on to the logging framework.
	global log_ssl: event(rec: Info);
}

# TODO: Maybe wrap these in @ifdef's? Otherwise we carry the extra baggage
# around all the time.
redef record Info += {
	sha1_digest: string &optional;
	notary: NotaryResponse &log &optional;
	};

redef record connection += {
	ssl: Info &optional;
};

# The DNS cache of notary responses.
global notary_cache: table[string] of NotaryResponse &create_expire = 1 hr;

# The buffered SSL log records.
global records: table[string] of Info;

# The records that wait for a notary response identified by the cert digest.
# Each digest refers to a list of connection UIDs which are updated when a DNS
# reply arrives asynchronously.
global waiting: table[string] of vector of string;

# A double-ended queue that determines the log record order in which logs have
# to written out to disk.
global deque: table[count] of string;

# The top-most deque index.
global head = 0;

# The bottom deque index that points to the next record to be flushed as soon
# as the notary response arrives.
global tail = 0;

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

function set_session(c: connection)
	{
	if ( ! c?$ssl )
		c$ssl = [$ts=network_time(), $uid=c$uid, $id=c$id, $cert_chain=vector(),
		         $client_cert_chain=vector()];
	}

function clear_waitlist(digest: string)
	{
	if ( digest in waiting )
		{
		for ( i in waiting[digest] )
			{
			local uid = waiting[digest][i];
			records[uid]$notary = [];
			}
		delete waiting[digest];
		}
	}

function lookup_cert_hash(uid: string, digest: string)
  {
  # Add the record ID to the list of waiting IDs for this digest.
  local waits_already = digest in waiting;
  if ( ! waits_already )
		waiting[digest] = vector();
	waiting[digest][|waiting[digest]|] = uid;
	if ( waits_already )
		return;

	local domain = "%s.notary.icsi.berkeley.edu";
	when ( local str = lookup_hostname_txt(fmt(domain, digest)) )
		{
		# Cache every response for a digest.
		# TODO: should we ignore failing answers?
		notary_cache[digest] = [];

		# Parse notary answer.
		if ( str == "<???>" )
			{
			# TODO: Should we handle NXDOMAIN separately?
			clear_waitlist(digest);
			return;
			}
		local fields = split(str, / /);
		if ( |fields| != 5 )	# version 1 has 5 fields.
			{
			clear_waitlist(digest);
			return;
			}
		local version = split(fields[1], /=/)[2];
		if ( version != "1" )
		{
			clear_waitlist(digest);
			return;
		}
		local r = notary_cache[digest];
		r$first_seen = to_count(split(fields[2], /=/)[2]);
		r$last_seen = to_count(split(fields[3], /=/)[2]);
		r$times_seen = to_count(split(fields[4], /=/)[2]);
		r$valid = split(fields[5], /=/)[2] == "1";

		# Assign notary answer to all waiting records.
		if ( digest in waiting )
		{
			for ( i in waiting[digest] )
				records[waiting[digest][i]]$notary = r;
			delete waiting[digest];
		}

		# Flush all records up to the record which still awaits an answer.
		local current: string;
		for ( unused_index in deque )
			{
				current = deque[tail];
				local info = records[current];
				if ( ! info?$notary )
					break;
				Log::write(SSL::LOG, info);
				delete deque[tail];
				delete records[current];
				++tail;
			}
		}
	}

function finish(c: connection)
	{
	if ( use_notary && c$ssl?$sha1_digest)
		{
		local digest = c$ssl$sha1_digest;
		if ( c$ssl$sha1_digest in notary_cache )
			c$ssl$notary = notary_cache[digest];
		else
			lookup_cert_hash(c$uid, digest);
		records[c$uid] = c$ssl; # Copy the record.
		deque[head] = c$uid;
		++head;
		}
	else
		{
		Log::write(SSL::LOG, c$ssl);
		}

	if ( disable_analyzer_after_detection && c?$ssl && c$ssl?$analyzer_id )
		disable_analyzer(c$id, c$ssl$analyzer_id);
	delete c$ssl;
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

			if ( use_notary )
				c$ssl$sha1_digest = sha1_hash(der_cert);
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
	if ( ! use_notary || |deque| == 0 )
		return;

	local current: string;
	for ( unused_index in deque )
		{
		current = deque[tail];
		local info = records[current];
		Log::write(SSL::LOG, info);
		delete deque[tail];
		delete records[current];
		++tail;
		}
	}
