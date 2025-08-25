##! Implements base functionality for WebSocket analysis.
##!
##! Upon a websocket_established() event, logs all gathered information into
##! websocket.log and configures the WebSocket analyzer with the headers
##! collected via http events.

@load base/protocols/http

@load ./consts

module WebSocket;

# Register the WebSocket analyzer as HTTP upgrade analyzer.
redef HTTP::upgrade_analyzers += {
	["websocket"] = Analyzer::ANALYZER_WEBSOCKET,
};

export {
	redef enum Log::ID += { LOG };

	## The record type for the WebSocket log.
	type Info: record {
		## Timestamp
		ts:                time    &log;
		## Unique ID for the connection.
		uid:               conn_uid &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                conn_id &log;
		## Same as in the HTTP log.
		host:              string &log &optional;
		## Same as in the HTTP log.
		uri:               string &log &optional;
		## Same as in the HTTP log.
		user_agent:        string &log &optional;
		## The WebSocket subprotocol as selected by the server.
		subprotocol:       string &log &optional;
		## The protocols requested by the client, if any.
		client_protocols:  vector of string &log &optional;
		## The extensions selected by the the server, if any.
		server_extensions: vector of string &log &optional;
		## The extensions requested by the client, if any.
		client_extensions: vector of string &log &optional;
		## The Sec-WebSocket-Key header from the client.
		client_key:        string &optional;
		## The Sec-WebSocket-Accept header from the server.
		server_accept:     string &optional;
	};

	## Event that can be handled to access the WebSocket record as it is
	## sent on to the logging framework.
	global log_websocket: event(rec: Info);

	## Log policy hook.
	global log_policy: Log::PolicyHook;

	## Experimental: Hook to intercept WebSocket analyzer configuration.
	##
	## Breaking from this hook disables the WebSocket analyzer immediately.
	## To modify the configuration of the analyzer, use the
	## :zeek:see:`WebSocket::AnalyzerConfig` type.
	##
	## While this API allows quite some flexibility currently, should be
	## considered experimental and may change in the future with or
	## without a deprecation phase.
	##
	## c: The connection
	##
	## aid: The analyzer ID for the WebSocket analyzer.
	##
	## config: The configuration record, also containing information
	##         about the subprotocol and extensions.
	global configure_analyzer: hook(c: connection, aid: count, config: AnalyzerConfig);
}

redef record connection += {
	websocket: Info &optional;
};

function set_websocket(c: connection)
	{
	c$websocket = Info(
		$ts=network_time(),
		$uid=c$uid,
		$id=c$id,
	);
	}

function expected_accept_for(key: string): string
	{
	return encode_base64(hexstr_to_bytestring(sha1_hash(key + HANDSHAKE_GUID)));
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ! starts_with(name, "SEC-WEBSOCKET-") )
		return;

	if ( ! c?$websocket )
		set_websocket(c);

	local ws = c$websocket;

	if ( is_orig )
		{
		if ( name == "SEC-WEBSOCKET-PROTOCOL" )
			{
			if ( ! ws?$client_protocols )
				ws$client_protocols = vector();

			ws$client_protocols += split_string(value, / *, */);
			}

		else if ( name == "SEC-WEBSOCKET-EXTENSIONS" )
			{
			if ( ! ws?$client_extensions )
				ws$client_extensions = vector();

			ws$client_extensions += split_string(value, / *, */);
			}
		else if ( name == "SEC-WEBSOCKET-KEY" )
			{
			if ( ws?$client_key )
				Reporter::conn_weird("websocket_multiple_key_headers", c, "", "WebSocket");

			ws$client_key = value;
			}
		}
	else
		{
		if ( name == "SEC-WEBSOCKET-PROTOCOL" )
			{
			if ( ws?$subprotocol )
				Reporter::conn_weird("websocket_multiple_protocol_headers", c, "", "WebSocket");

			ws$subprotocol = value;
			}
		else if ( name == "SEC-WEBSOCKET-EXTENSIONS" )
			{
			if ( ! ws?$server_extensions )
				ws$server_extensions = vector();

			ws$server_extensions += split_string(value, / *, */);
			}
		else if ( name == "SEC-WEBSOCKET-ACCEPT" )
			{
			if ( ws?$server_accept )
				Reporter::conn_weird("websocket_multiple_accept_headers", c, "", "WebSocket");

			ws$server_accept = value;
			}
		}
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{
	# If we see a http_request and have websocket state, wipe it as
	# we should've seen a websocket_established even on success and
	# likely no more http events.
	if ( ! c?$websocket )
		delete c$websocket;
	}

event websocket_established(c: connection, aid: count) &priority=5
	{
	if ( ! c?$websocket )
		{
		# This means we never saw a Sec-WebSocket-* header, weird.
		Reporter::conn_weird("websocket_established_unexpected", c, "", "WebSocket");
		set_websocket(c);
		}

	local ws = c$websocket;

	if ( ! ws?$client_key )
		Reporter::conn_weird("websocket_missing_key_header", c, "", "WebSocket");

	if ( ! ws?$server_accept )
		Reporter::conn_weird("websocket_missing_accept_header", c, "", "WebSocket");

	# Verify the Sec-WebSocket-Accept header's value given the Sec-WebSocket-Key header's value.
	if ( ws?$client_key && ws?$server_accept )
		{
		local expected_accept = expected_accept_for(ws$client_key);
		if ( ws$server_accept != expected_accept )
			Reporter::conn_weird("websocket_wrong_accept_header", c,
			                     fmt("expected=%s, found=%s", expected_accept, ws$server_accept),
			                     "WebSocket");
		}

	# Replicate some information from the HTTP.log
	if ( c?$http )
		{
		if ( c$http?$host )
			ws$host = c$http$host;

		if ( c$http?$uri )
			ws$uri = c$http$uri;

		if ( c$http?$user_agent )
			ws$user_agent = c$http$user_agent;
		}
	}

event websocket_established(c: connection, aid: count) &priority=-5
	{
	local ws = c$websocket;

	local config = AnalyzerConfig();
	if ( ws?$subprotocol )
		config$subprotocol = ws$subprotocol;

	if ( ws?$server_extensions )
		config$server_extensions = ws$server_extensions;

	# Give other scripts a chance to modify the analyzer configuration.
	#
	# Breaking from this hook disables the new WebSocket analyzer
	# completely instead of configuring it.
	if ( hook WebSocket::configure_analyzer(c, aid, config) )
		WebSocket::__configure_analyzer(c, aid, config);
	else
		disable_analyzer(c$id, aid);

	ws$ts = network_time();
	Log::write(LOG, ws);
	}

event zeek_init()
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_websocket, $path="websocket", $policy=log_policy));
	}
