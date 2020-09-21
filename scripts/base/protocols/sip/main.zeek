##! Implements base functionality for SIP analysis.  The logging model is
##! to log request/response pairs and all relevant metadata together in
##! a single record.

@load base/utils/numbers
@load base/utils/files
@load base/protocols/conn/removal-hooks

module SIP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## The record type which contains the fields of the SIP log.
	type Info: record {
		## Timestamp for when the request happened.
		ts:                      time              &log;
		## Unique ID for the connection.
		uid:                     string            &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                      conn_id           &log;
		## Represents the pipelined depth into the connection of this
		## request/response transaction.
		trans_depth:             count             &log;
		## Verb used in the SIP request (INVITE, REGISTER etc.).
		method:                  string            &log &optional;
		## URI used in the request.
		uri:                     string            &log &optional;
		## Contents of the Date: header from the client
		date:                    string            &log &optional;
		## Contents of the request From: header
		## Note: The tag= value that's usually appended to the sender
		## is stripped off and not logged.
		request_from:            string            &log &optional;
		## Contents of the To: header
		request_to:              string            &log &optional;
		## Contents of the response From: header
		## Note: The ``tag=`` value that's usually appended to the sender
		## is stripped off and not logged.
		response_from:            string            &log &optional;
		## Contents of the response To: header
		response_to:              string            &log &optional;

		## Contents of the Reply-To: header
		reply_to:                string            &log &optional;
		## Contents of the Call-ID: header from the client
		call_id:                 string            &log &optional;
		## Contents of the CSeq: header from the client
		seq:                     string            &log &optional;
		## Contents of the Subject: header from the client
		subject:                 string            &log &optional;
		## The client message transmission path, as extracted from the headers.
		request_path:            vector of string  &log &optional;
		## The server message transmission path, as extracted from the headers.
		response_path:           vector of string  &log &optional;
		## Contents of the User-Agent: header from the client
		user_agent:              string            &log &optional;
		## Status code returned by the server.
		status_code:             count             &log &optional;
		## Status message returned by the server.
		status_msg:              string            &log &optional;
		## Contents of the Warning: header
		warning:                 string            &log &optional;
		## Contents of the Content-Length: header from the client
		request_body_len:        count             &log &optional;
		## Contents of the Content-Length: header from the server
		response_body_len:       count             &log &optional;
		## Contents of the Content-Type: header from the server
		content_type:            string            &log &optional;
	};

	type State: record {
		## Pending requests.
		pending:          table[count] of Info;
		## Current request in the pending queue.
		current_request:  count                &default=0;
		## Current response in the pending queue.
		current_response: count                &default=0;
	};

	## A list of SIP methods. Other methods will generate a weird. Note
	## that the SIP analyzer will only accept methods consisting solely
	## of letters ``[A-Za-z]``.
	option sip_methods: set[string] = {
		"REGISTER", "INVITE", "ACK", "CANCEL", "BYE", "OPTIONS", "NOTIFY", "SUBSCRIBE"
	};

	## Event that can be handled to access the SIP record as it is sent on
	## to the logging framework.
	global log_sip: event(rec: Info);

	## SIP finalization hook.  Remaining SIP info may get logged when it's called.
	global finalize_sip: Conn::RemovalHook;
}

# Add the sip state tracking fields to the connection record.
redef record connection += {
	sip:        Info  &optional;
	sip_state:  State &optional;
};

const ports = { 5060/udp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(SIP::LOG, [$columns=Info, $ev=log_sip, $path="sip", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SIP, ports);
	}

function new_sip_session(c: connection): Info
	{
	local tmp: Info;
	tmp$ts=network_time();
	tmp$uid=c$uid;
	tmp$id=c$id;
	# $current_request is set prior to the Info record creation so we
	# can use the value directly here.
	tmp$trans_depth = c$sip_state$current_request;

	tmp$request_path = vector();
	tmp$response_path = vector();

	return tmp;
	}

function set_state(c: connection, is_request: bool)
	{
	if ( ! c?$sip_state )
		{
		local s: State;
		c$sip_state = s;
		Conn::register_removal_hook(c, finalize_sip);
		}

	if ( is_request )
		{
		if ( c$sip_state$current_request !in c$sip_state$pending )
			c$sip_state$pending[c$sip_state$current_request] = new_sip_session(c);

		c$sip = c$sip_state$pending[c$sip_state$current_request];
		}
	else
		{
		if ( c$sip_state$current_response !in c$sip_state$pending )
			c$sip_state$pending[c$sip_state$current_response] = new_sip_session(c);

		c$sip = c$sip_state$pending[c$sip_state$current_response];
		}
	}

function flush_pending(c: connection)
	{
	# Flush all pending but incomplete request/response pairs.
	if ( c?$sip_state )
		{
		for ( r, info in c$sip_state$pending )
			{
			# We don't use pending elements at index 0.
			if ( r == 0 )
				next;

			Log::write(SIP::LOG, info);
			}
		}
	}

event sip_request(c: connection, method: string, original_URI: string, version: string) &priority=5
	{
	set_state(c, T);

	c$sip$method = method;
	c$sip$uri = original_URI;

	if ( method !in sip_methods )
		Reporter::conn_weird("unknown_SIP_method", c, method);
	}

event sip_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	set_state(c, F);

	if ( c$sip_state$current_response !in c$sip_state$pending &&
	     (code < 100 && 200 <= code) )
		++c$sip_state$current_response;

	c$sip$status_code = code;
	c$sip$status_msg = reason;
	}

event sip_header(c: connection, is_request: bool, name: string, value: string) &priority=5
	{
	if ( ! c?$sip_state )
		{
		local s: State;
		c$sip_state = s;
		Conn::register_removal_hook(c, finalize_sip);
		}

	if ( is_request ) # from client
		{
		if ( c$sip_state$current_request !in c$sip_state$pending )
			++c$sip_state$current_request;
		set_state(c, is_request);
		switch ( name )
			{
			case "CALL-ID":
				c$sip$call_id = value;
				break;
			case "CONTENT-LENGTH", "L":
				c$sip$request_body_len = to_count(value);
				break;
			case "CSEQ":
				c$sip$seq = value;
				break;
			case "DATE":
				c$sip$date = value;
				break;
			case "FROM", "F":
				c$sip$request_from = split_string1(value, /;[ ]?tag=/)[0];
				break;
			case "REPLY-TO":
				c$sip$reply_to = value;
				break;
			case "SUBJECT", "S":
				c$sip$subject = value;
				break;
			case "TO", "T":
				c$sip$request_to = value;
				break;
			case "USER-AGENT":
				c$sip$user_agent = value;
				break;
			case "VIA", "V":
				c$sip$request_path += split_string1(value, /;[ ]?branch/)[0];
				break;
			}

		c$sip_state$pending[c$sip_state$current_request] = c$sip;
		}
	else # from server
		{
		if ( c$sip_state$current_response !in c$sip_state$pending )
			++c$sip_state$current_response;

		set_state(c, is_request);
		switch ( name )
			{
			case "CONTENT-LENGTH", "L":
				c$sip$response_body_len = to_count(value);
				break;
			case "CONTENT-TYPE", "C":
				c$sip$content_type = value;
				break;
			case "WARNING":
				c$sip$warning = value;
				break;
			case "FROM", "F":
				c$sip$response_from = split_string1(value, /;[ ]?tag=/)[0];
				break;
			case "TO", "T":
				c$sip$response_to = value;
				break;
			case "VIA", "V":
				c$sip$response_path += split_string1(value, /;[ ]?branch/)[0];
				break;
			}

		c$sip_state$pending[c$sip_state$current_response] = c$sip;
		}
	}

event sip_end_entity(c: connection, is_request: bool) &priority = 5
	{
	set_state(c, is_request);
	}

event sip_end_entity(c: connection, is_request: bool) &priority = -5
	{
	# The reply body is done so we're ready to log.
	if ( ! is_request )
		{
		Log::write(SIP::LOG, c$sip);

		if ( c$sip$status_code < 100 || 200 <= c$sip$status_code )
			delete c$sip_state$pending[c$sip_state$current_response];

		if ( ! c$sip?$method || ( c$sip$method == "BYE" &&
		     c$sip$status_code >= 200 && c$sip$status_code < 300 ) )
			{
			flush_pending(c);
			delete c$sip;
			delete c$sip_state;
			}
		}
	}

hook finalize_sip(c: connection)
	{
	if ( c?$sip_state )
		{
		for ( r, info in c$sip_state$pending )
			{
			Log::write(SIP::LOG, info);
			}
		}
	}

