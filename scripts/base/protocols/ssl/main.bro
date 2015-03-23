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
		uid:              string           &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id          &log;
		## SSL/TLS version that the server offered.
		version:          string           &log &optional;
		## SSL/TLS cipher suite that the server chose.
		cipher:           string           &log &optional;
		## Elliptic curve the server chose when using ECDH/ECDHE.
		curve:            string           &log &optional;
		## Value of the Server Name Indicator SSL/TLS extension.  It
		## indicates the server name that the client was requesting.
		server_name:      string           &log &optional;
		## Session ID offered by the client for session resumption.
		## Not used for logging.
		session_id:       string           &optional;
		## Flag to indicate if the session was resumed reusing
		## the key material exchanged in an earlier connection.
		resumed:          bool             &log &default=F;
		## Flag to indicate if we saw a non-empty session ticket being
		## sent by the client using an empty session ID. This value
		## is used to determine if a session is being resumed. It's
		## not logged.
		client_ticket_empty_session_seen: bool &default=F;
		## Flag to indicate if we saw a client key exchange message sent
		## by the client. This value is used to determine if a session
		## is being resumed. It's not logged.
		client_key_exchange_seen: bool     &default=F;
		## Last alert that was seen during the connection.
		last_alert:       string           &log &optional;
		## Next protocol the server chose using the application layer
		## next protocol extension, if present.
		next_protocol:    string           &log &optional;

		## The analyzer ID used for the analyzer instance attached
		## to each connection.  It is not used for logging since it's a
		## meaningless arbitrary number.
		analyzer_id:      count            &optional;

		## Flag to indicate if this ssl session has been established
		## succesfully, or if it was aborted during the handshake.
		established:      bool             &log &default=F;

		## Flag to indicate if this record already has been logged, to
		## prevent duplicates.
		logged:           bool             &default=F;
	};

	## The default root CA bundle.  By default, the mozilla-ca-list.bro
	## script sets this to Mozilla's root CA list.
	const root_certs: table[string] of string = {} &redef;

	## If true, detach the SSL analyzer from the connection to prevent
	## continuing to process encrypted traffic. Helps with performance
	## (especially with large file transfers).
	const disable_analyzer_after_detection = T &redef;

	## Delays an SSL record for a specific token: the record will not be
	## logged as long as the token exists or until 15 seconds elapses.
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
		# the record has been delayed.
		delay_tokens: set[string] &optional;
};

const ssl_ports = {
	443/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
	989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp, 5223/tcp
};

# There are no well known DTLS ports at the moment. Let's
# just add 443 for now for good measure - who knows :)
const dtls_ports = { 443/udp };

redef likely_server_ports += { ssl_ports, dtls_ports };

event bro_init() &priority=5
	{
	Log::create_stream(SSL::LOG, [$columns=Info, $ev=log_ssl, $path="ssl"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSL, ssl_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DTLS, dtls_ports);
	}

function set_session(c: connection)
	{
	if ( ! c?$ssl )
		c$ssl = [$ts=network_time(), $uid=c$uid, $id=c$id];
	}

function delay_log(info: Info, token: string)
	{
	if ( ! info?$delay_tokens )
		info$delay_tokens = set();
	add info$delay_tokens[token];
	}

function undelay_log(info: Info, token: string)
	{
	if ( info?$delay_tokens && token in info$delay_tokens )
		delete info$delay_tokens[token];
	}

function log_record(info: Info)
	{
	if ( info$logged )
		return;

	if ( ! info?$delay_tokens || |info$delay_tokens| == 0 )
		{
		Log::write(SSL::LOG, info);
		info$logged = T;
		}
	else
		{
		when ( |info$delay_tokens| == 0 )
			{
			log_record(info);
			}
		timeout 15secs
			{
			# We are just going to log the record anyway.
			delete info$delay_tokens;
			log_record(info);
			}
		}
	}

# remove_analyzer flag is used to prevent disabling analyzer for finished
# connections.
function finish(c: connection, remove_analyzer: bool)
	{
	log_record(c$ssl);
	if ( remove_analyzer && disable_analyzer_after_detection && c?$ssl && c$ssl?$analyzer_id )
		{
		disable_analyzer(c$id, c$ssl$analyzer_id);
		delete c$ssl$analyzer_id;
		}
	}

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=5
	{
	set_session(c);

	# Save the session_id if there is one set.
	if ( |session_id| > 0 && session_id != /^\x00{32}$/ )
		{
		c$ssl$session_id = bytestring_to_hexstr(session_id);
		c$ssl$client_ticket_empty_session_seen = F;
		}
	}

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=5
	{
	set_session(c);

	c$ssl$version = version_strings[version];
	c$ssl$cipher = cipher_desc[cipher];

	if ( c$ssl?$session_id && c$ssl$session_id == bytestring_to_hexstr(session_id) )
		c$ssl$resumed = T;
	}

event ssl_server_curve(c: connection, curve: count) &priority=5
	{
	set_session(c);

	c$ssl$curve = ec_curves[curve];
	}

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec) &priority=5
	{
	set_session(c);

	if ( is_orig && |names| > 0 )
		{
		c$ssl$server_name = names[0];
		if ( |names| > 1 )
			event conn_weird("SSL_many_server_names", c, cat(names));
		}
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_orig: bool, protocols: string_vec)
	{
	set_session(c);

	if ( is_orig )
		return;

	if ( |protocols| > 0 )
		c$ssl$next_protocol = protocols[0];
	}

event ssl_handshake_message(c: connection, is_orig: bool, msg_type: count, length: count) &priority=5
	{
	set_session(c);

	if ( is_orig && msg_type == SSL::CLIENT_KEY_EXCHANGE )
		c$ssl$client_key_exchange_seen = T;
	}

# Extension event is fired _before_ the respective client or server hello.
# Important for client_ticket_empty_session_seen.
event ssl_extension(c: connection, is_orig: bool, code: count, val: string) &priority=5
	{
	set_session(c);

	if ( is_orig && SSL::extensions[code] == "SessionTicket TLS" && |val| > 0 )
		# In this case, we might have an empty ID. Set back to F in client_hello event
		# if it is not empty after all.
		c$ssl$client_ticket_empty_session_seen = T;
	}

event ssl_change_cipher_spec(c: connection, is_orig: bool) &priority=5
	{
	set_session(c);

	if ( is_orig && c$ssl$client_ticket_empty_session_seen && ! c$ssl$client_key_exchange_seen )
		c$ssl$resumed = T;
	}

event ssl_alert(c: connection, is_orig: bool, level: count, desc: count) &priority=5
	{
	set_session(c);

	c$ssl$last_alert = alert_descriptions[desc];
	}

event ssl_established(c: connection) &priority=7
	{
	set_session(c);
	c$ssl$established = T;
	}

event ssl_established(c: connection) &priority=-5
	{
	finish(c, T);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$ssl )
		# called in case a SSL connection that has not been established terminates
		finish(c, F);
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_SSL || atype == Analyzer::ANALYZER_DTLS )
		{
		set_session(c);
		c$ssl$analyzer_id = aid;
		}
	}

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count,
                         reason: string) &priority=5
	{
	if ( c?$ssl && ( atype == Analyzer::ANALYZER_SSL || atype == Analyzer::ANALYZER_DTLS ) )
		finish(c, T);
	}
