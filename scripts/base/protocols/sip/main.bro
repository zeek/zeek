##! Implements base functionality for SIP analysis.  The logging model is
##! to log request/response pairs and all relevant metadata together in
##! a single record.

@load base/utils/numbers
@load base/utils/files

module SIP;

export {
	redef enum Log::ID += { LOG };

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
		request_body_len:        string            &log &optional;
		## Contents of the Content-Length: header from the server
		response_body_len:       string            &log &optional;
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
	const sip_methods: set[string] = {
		"REGISTER", "INVITE", "ACK", "CANCEL", "BYE", "OPTIONS"
	} &redef;

	## Event that can be handled to access the SIP record as it is sent on
	## to the logging framework.
	global log_sip: event(rec: Info);
}

# Add the sip state tracking fields to the connection record.
redef record connection += {
	sip:        Info  &optional;
	sip_state:  State &optional;
};

const ports = { 5060/udp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(SIP::LOG, [$columns=Info, $ev=log_sip, $path="sip"]);
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
		}

	# These deal with new requests and responses.
	if ( is_request && c$sip_state$current_request !in c$sip_state$pending )
		c$sip_state$pending[c$sip_state$current_request] = new_sip_session(c);
	if ( ! is_request && c$sip_state$current_response !in c$sip_state$pending )
		c$sip_state$pending[c$sip_state$current_response] = new_sip_session(c);

	if ( is_request )
		c$sip = c$sip_state$pending[c$sip_state$current_request];
	else
		c$sip = c$sip_state$pending[c$sip_state$current_response];

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
		for ( r in c$sip_state$pending )
			{
			# We don't use pending elements at index 0.
			if ( r == 0 ) next;
			Log::write(SIP::LOG, c$sip_state$pending[r]);
			}
		}
	}

event sip_request(c: connection, method: string, original_URI: string, version: string) &priority=5
	{
	set_state(c, T);

	c$sip$method = method;
	c$sip$uri = original_URI;

	if ( method !in sip_methods )
		event conn_weird("unknown_SIP_method", c, method);
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
		}

	if ( is_request ) # from client
		{
		if ( c$sip_state$current_request !in c$sip_state$pending )
			++c$sip_state$current_request;
		set_state(c, is_request);
		if ( name == "CALL-ID" )                            c$sip$call_id = value;
		else if ( name == "CONTENT-LENGTH" || name == "L" ) c$sip$request_body_len = value;
		else if ( name == "CSEQ" )                          c$sip$seq = value;
		else if ( name == "DATE" )                          c$sip$date = value;
		else if ( name == "FROM" || name == "F" )           c$sip$request_from = split_string1(value, /;[ ]?tag=/)[0];
		else if ( name == "REPLY-TO" )                      c$sip$reply_to = value;
		else if ( name == "SUBJECT" || name == "S" )        c$sip$subject = value;
		else if ( name == "TO" || name == "T" )             c$sip$request_to = value;
		else if ( name == "USER-AGENT" )                    c$sip$user_agent = value;
		else if ( name == "VIA" || name == "V" )            c$sip$request_path[|c$sip$request_path|] = split_string1(value, /;[ ]?branch/)[0];

		c$sip_state$pending[c$sip_state$current_request] = c$sip;
		}
	else # from server
		{
		if ( c$sip_state$current_response !in c$sip_state$pending )
			++c$sip_state$current_response;
		set_state(c, is_request);
		if ( name == "CONTENT-LENGTH" || name == "L" )    c$sip$response_body_len = value;
		else if ( name == "CONTENT-TYPE" || name == "C" ) c$sip$content_type = value;
		else if ( name == "WARNING" )                     c$sip$warning = value;
		else if ( name == "FROM" || name == "F" )         c$sip$response_from = split_string1(value, /;[ ]?tag=/)[0];
		else if ( name == "TO" || name == "T" )           c$sip$response_to = value;
		else if ( name == "VIA" || name == "V" )          c$sip$response_path[|c$sip$response_path|] = split_string1(value, /;[ ]?branch/)[0];

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

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$sip_state )
		{
		for ( r in c$sip_state$pending )
			{
			Log::write(SIP::LOG, c$sip_state$pending[r]);
			}
		}
	}

