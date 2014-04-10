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
		## Last alert that was seen during the connection.
		last_alert:       string           &log &optional;

		## The analyzer ID used for the analyzer instance attached
		## to each connection.  It is not used for logging since it's a
		## meaningless arbitrary number.
		analyzer_id:      count            &optional;

		## Flag to indicate if this ssl session has been established
		## succesfully, or if it was aborted during the handshake.
		established:  bool &log &default=F;

		## Flag to indicate if this record already has been logged, to
		## prevent duplicates.
		logged:  bool  &default=F;
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

const ports = {
	443/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
	989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp, 5223/tcp
};
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(SSL::LOG, [$columns=Info, $ev=log_ssl]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSL, ports);
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
	if ( session_id != /^\x00{32}$/ )
		c$ssl$session_id = bytestring_to_hexstr(session_id);
	}

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=5
	{
	set_session(c);

	c$ssl$version = version_strings[version];
	c$ssl$cipher = cipher_desc[cipher];
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
	if ( atype == Analyzer::ANALYZER_SSL ) 
		{
		set_session(c);
		c$ssl$analyzer_id = aid;
		}
	}

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count,
                         reason: string) &priority=5
	{
	if ( c?$ssl )
		finish(c, T);
	}
