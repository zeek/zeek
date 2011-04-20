@load functions

module HTTP;

redef enum Log::ID += { HTTP };

export {
	## Indicate a type of attack or compromise in the record to be logged.
	type Tags: enum {
		EMPTY
	};
	
	type LogPoint: enum { 
		AFTER_REQUEST,
		AFTER_REQUEST_BODY,
		AFTER_REPLY, 
		AFTER_REPLY_BODY,
	};
	
	## Define the default point at which you'd like the logging to take place.
	## If you wait until after the reply body, you can be assured that you will
	## get the most data, but at the expense of a delayed log which could
	## be substantial in the event of a large file download.  It's typically
	## not much of a problem.  To mitigate, you may want to change this value
	## to AFTER_REPLY which will cause the log action to take place after all
	## of the response headers.
	## This is settable per-session too by setting the $log_point value
	## in a SessionInfo record.
	const default_log_point = AFTER_REPLY &redef;
	
	type State: record {
		ts:                      time     &log;
		id:                      conn_id  &log;
		method:                  string   &log &optional;
		host:                    string   &log &optional;
		uri:                     string   &log &optional;
		referrer:                string   &log &optional;
		user_agent:              string   &log &optional;
		request_content_length:  count    &log &optional;
		response_content_length: count    &log &optional;
		status_code:             count    &log &optional;
		status_msg:              string   &log &optional;
		## This is a set of indicators of various attributes discovered and
		## related to a particular request/response pair.
		tags:                    set[Tags] &log &optional;
		
		#file_name: string; ##maybe if the header's there?
		
		log_point:               LogPoint &default=default_log_point;
	};
	
	global log_http: event(rec: State);
}

# Add the http state tracking field to the connection record.
redef record connection += {
	http: State &optional;
	http_pending: table[count] of State &optional;
	http_current_response: count &default=0;
};

# Initialize the HTTP logging stream.
event bro_init()
	{
	Log::create_stream(HTTP, [$columns=State, $ev=log_http]);
	}

# DPD configuration.
const ports = {
	80/tcp, 81/tcp, 631/tcp, 1080/tcp, 3138/tcp,
	8000/tcp, 8080/tcp, 8888/tcp,
};
redef dpd_config += { 
	[[ANALYZER_HTTP, ANALYZER_HTTP_BINPAC]] = [$ports = ports],
};
redef capture_filters +=  {
	["http"] = "tcp and port (80 or 81 or 631 or 1080 or 3138 or 8000 or 8080 or 8888)"
};

function new_http_session(c: connection): State
	{
	local tmp: State;
	tmp$ts=network_time();
	tmp$id=c$id;
	# TODO: remove this when &default on this set isn't segfaulting Bro anymore.
	tmp$tags = set();
	return tmp;
	}
	
function set_state(c: connection, request: bool, initial: bool)
	{
	if ( ! c?$http_pending )
		c$http_pending = table();
	
	# This handles each new request in a pipeline and the case where there
	# is a response before any request.
	if ( (request && initial) || |c$http_pending| == 0 )
		# TODO: need some FIFO operations on vectors and/or sets.
		c$http_pending[|c$http_pending|+1] = new_http_session(c);
	
	if ( request )
		{
		# Save the existing c$http back to the correct place in http_pending.
		# TODO: understand why this isn't just updated correctly since it's 
		#       all pointers internally.
		if ( ! initial )
			c$http_pending[|c$http_pending|] = c$http;
		c$http = c$http_pending[|c$http_pending|];
		}
	else
		{
		if ( ! initial )
			c$http_pending[c$http_current_response] = c$http;
		if ( c$http_current_response in c$http_pending )
			{
			c$http = c$http_pending[c$http_current_response];
			}
		else
			c$http = c$http_pending[|c$http_pending|];
		}
	
	#print c$http_pending;
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
	{
	#print "http_request";
	set_state(c, T, T);
	
	c$http$method = method;
	c$http$uri = unescaped_URI;
	}
	
event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	#print "http reply";
	++c$http_current_response;
	set_state(c, F, T);
	
	c$http$status_code = code;
	c$http$status_msg = reason;
	}
	
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
	{
	#print "http_header";
	set_state(c, is_orig, F);
	
	if ( is_orig ) # client headers
		{
		if ( name == "REFERER" )
			c$http$referrer = value;

		else if ( name == "HOST" )
			c$http$host = value;
		
		else if ( name == "CONTENT-LENGTH" )
			c$http$request_content_length = to_count(value);
			
		else if ( name == "USER-AGENT" )
			{
			c$http$user_agent = value;
			}
		
		}
	else # server headers
		{
		if ( name == "CONTENT-LENGTH" )
			c$http$response_content_length = to_count(value);
		}
	
	#if ( is_orig )
	#	c$http_pending[|c$http_pending|] = c$http;
	#else
	#	c$http_pending[c$http_current_response] = c$http;
	}
	
#event http_begin_entity(c: connection, is_orig: bool) &priority=5
#	{
#	set_state(c, is_orig, F);
#	}
	

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-5
	{
	#print "message done";
	set_state(c, is_orig, F);

	if ( is_orig )
		{
		if ( c$http$log_point == AFTER_REQUEST )
			Log::write(HTTP, c$http);
		}
	else
		{
		if ( c$http$log_point == AFTER_REPLY )
			{
			#print "logging";
			Log::write(HTTP, c$http);
			}
		}
	}
	
event connection_state_remove(c: connection)
	{
	# TODO: flush any unmatched requests
	
	#if ( c?$http && c$http$log_point == BEFORE_NEXT_REQUEST )
	#	Log::write(HTTP, c$http);
	}
	
