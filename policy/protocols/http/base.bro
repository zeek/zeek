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
	## be substantial in the event of a large file download, but it's typically
	## not much of a problem.  To mitigate, you may want to change this value
	## to AFTER_REPLY which will cause the log action to take place after all
	## of the response headers.
	## This is settable per-session too by setting the $log_point value
	## in an Info record to another of the LogPoint enum values.
	const default_log_point: LogPoint = AFTER_REPLY &redef;
	
	type Info: record {
		ts:                      time     &log;
		uid:                     string   &log;
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
		tags:                    set[Tags] &log;
		
		#file_name: string; ##maybe if the header's there?
		
		log_point:               LogPoint &default=default_log_point;
	};
	
	type State: record {
		pending:          table[count] of Info;
		current_response: count                &default=0;
		current_request:  count                &default=0;
	};
	
	global log_http: event(rec: Info);
}

# Add the http state tracking field to the connection record.
redef record connection += {
	http:        Info  &optional;
	http_state:  State &optional;
};

# Initialize the HTTP logging stream.
event bro_init()
	{
	Log::create_stream(HTTP, [$columns=Info, $ev=log_http]);
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

function new_http_session(c: connection): Info
	{
	local tmp: Info;
	tmp$ts=network_time();
	tmp$uid=c$uid;
	tmp$id=c$id;
	return tmp;
	}
	
function set_state(c: connection, request: bool, is_orig: bool)
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		}
	
	# These deal with new requests and responses.
	if ( request || c$http_state$current_request !in c$http_state$pending )
		c$http_state$pending[c$http_state$current_request] = new_http_session(c);
	if ( ! is_orig && c$http_state$current_response !in c$http_state$pending )
		c$http_state$pending[c$http_state$current_response] = new_http_session(c);
	
	if ( is_orig )
		c$http = c$http_state$pending[c$http_state$current_request];
	else
		c$http = c$http_state$pending[c$http_state$current_response];
	}
	
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		}
	
	++c$http_state$current_request;
	set_state(c, T, T);
	
	c$http$method = method;
	c$http$uri = unescaped_URI;
	}
	
event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		}
	
	++c$http_state$current_response;
	set_state(c, F, F);
	
	c$http$status_code = code;
	c$http$status_msg = reason;
	}
	
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
	{
	set_state(c, F, is_orig);
	
	if ( is_orig ) # client headers
		{
		if ( name == "REFERER" )
			c$http$referrer = value;

		else if ( name == "HOST" )
			# The split is done to remove the occasional port value that shows up here.
			c$http$host = split1(value, /:/)[1];
		
		else if ( name == "CONTENT-LENGTH" )
			c$http$request_content_length = to_count(strip(value));
			
		else if ( name == "USER-AGENT" )
			c$http$user_agent = value;
		}
	else # server headers
		{
		if ( name == "CONTENT-LENGTH" )
			c$http$response_content_length = to_count(strip(value));
		}
	}
	
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=5
	{
	set_state(c, F, is_orig);
	}
	
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-5
	{
	# For some reason the analyzer seems to generate this event an extra time 
	# when there is an interruption.  I'm not sure what's going on with that.
	if ( stat$interrupted )
		return;
	
	if ( is_orig && c$http$log_point == AFTER_REQUEST )
		{
		Log::write(HTTP, c$http);
		delete c$http_state$pending[c$http_state$current_request];
		}
	
	if ( ! is_orig && c$http$log_point == AFTER_REPLY )
		{
		Log::write(HTTP, c$http);
		delete c$http_state$pending[c$http_state$current_response];
		}
	}

event http_end_entity(c: connection, is_orig: bool) &priority=5
	{
	set_state(c, F, is_orig);
	}
	
# I don't like handling the AFTER_*_BODY handling this way, but I'm not
# seeing another post-body event to handle.
event http_end_entity(c: connection, is_orig: bool) &priority=-5
	{
	if ( is_orig && c$http$log_point == AFTER_REQUEST_BODY )
		{
		Log::write(HTTP, c$http);
		delete c$http_state$pending[c$http_state$current_request];
		}

	if ( ! is_orig && c$http$log_point == AFTER_REPLY_BODY )
		{
		Log::write(HTTP, c$http);
		delete c$http_state$pending[c$http_state$current_response];
		}
	}
	
event connection_state_remove(c: connection)
	{
	# Flush all unmatched requests.
	if ( c?$http_state )
		{
		for ( r in c$http_state$pending )
			Log::write(HTTP, c$http_state$pending[r] );
		}
	}
	
