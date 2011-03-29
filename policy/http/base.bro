##! Yay, this is the new HTTP script

## Author: Seth Hall <seth@icir.org> - Inspired by the work of many others.

@load functions
@load notice
@load software

module HTTP;

redef enum Software::Type += {
	WEB_SERVER,
	WEB_BROWSER,
	WEB_BROWSER_PLUGIN,
};

redef enum Log::ID += { HTTP };

export {
	## Indicate a type of attack or compromise in the record to be logged.
	type LogTags: enum {
		EMTPY
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
	const default_log_point = AFTER_REPLY_BODY &redef;
	
	type State: record {
		ts:                 time    &log;
		id:                 conn_id &log;
		method:             string  &log &default="";
		host:               string  &log &default="";
		uri:                string  &log &default="";
		referrer:           string  &log &default="";
		user_agent:         string  &log &default="";
		request_body_size:  count   &log &default=0;
		response_body_size: count   &log &default=0;
		status_code:        count   &log &default=0;
		status_msg:         string  &log &default="";
		## This is a set of indicators of various attributes discovered and
		## related to a particular request/response pair.
		tags:               set[LogTags] &log;
		
		# Do these in a separate script.
		#mime_type:   string &default="";
		#generate_md5: bool &default=F;
		#md5: string &default="";
		#file_name: string; ##maybe if the header's there?
		
		#pending_requests: Request;
		log_point:        LogPoint &default=default_log_point;
	};
	
	## List of all active HTTP session indexed by conn_id.
	#global active_conns: table[conn_id] of SessionInfo &read_expire=5mins;
	
	global log_http: event(rec: State);
}

# Add the http state tracking field to the connection record.
redef record connection += {
	http: State &optional;
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
	local tags: set[LogTags] = set();
	local proxied: set[string] = set();
	local tmp: State = [$ts=network_time(), $id=c$id, $tags=tags, $proxied=proxied];
	return tmp;
	}

function set_http_session(c: connection)
	{
	if ( ! c?$http )
		c$http = new_http_session(c);
	}

function do_log(c: connection)
	{
	Log::write(HTTP, c$http);
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
	{
	set_http_session(c);
	
	c$http$method = method;
	c$http$uri = unescaped_URI;
	}
	
event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	set_http_session(c);

	c$http$status_code = code;
	c$http$status_msg = reason;
	}
	
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
	{
	set_http_session(c);
	
	if ( is_orig ) # client headers
		{
		if ( name == "REFERER" )
			c$http$referrer = value;

		else if ( name == "HOST" )
			c$http$host = value;
		
		else if ( name == "CONTENT-LENGTH" )
			c$http$request_body_size = to_count(value);
			
		else if ( name == "USER-AGENT" )
			{
			c$http$user_agent = value;
	        #
			#if ( ignored_user_agents in value ) 
			#	return;
	        #
			#if ( /Java\// in value )
			#	{
			#	local java_tokens = split_n(value, /Java\//, F, 2);
			#	if ( |java_tokens| == 2 )
			#		{
			#		local java_string = fmt("Java/%s", java_tokens[2]);
			#		local java_ver = default_software_parsing(java_string);
			#		event software_version_found(c, c$id$orig_h, 
			#		                             java_ver,
			#		                             WEB_BROWSER_PLUGIN);
			#		}
			#	}
	        #
			#if ( addr_matches_hosts(c$id$orig_h, track_user_agents_for) &&
			#	 value !in known_user_agents[c$id$orig_h] )
			#	{
			#	if ( c$id$orig_h !in known_user_agents )
			#		known_user_agents[c$id$orig_h] = set();
			#	add known_user_agents[c$id$orig_h][value];
			#	ci$new_user_agent = T;
			#	}
			}
		
		}
	else # server headers
		{
		if ( name == "SERVER" )
			{
			local si = Software::parse(value, c$id$resp_h, WEB_SERVER);
			Software::found(c, si);
			}
		else if ( name == "CONTENT-LENGTH" )
			c$http$response_body_size = to_count(value);
		}
	}
	
event http_begin_entity(c: connection, is_orig: bool) &priority=-5
	{
	set_http_session(c);
	
	if ( is_orig )
		if ( c$http$log_point == AFTER_REQUEST )
			do_log(c);
	else
		if ( c$http$log_point == AFTER_REPLY )
			do_log(c);
	}
	
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-5
	{
	set_http_session(c);
	
	if ( is_orig )
		if ( c$http$log_point == AFTER_REQUEST_BODY ) 
			do_log(c);
	else
		if ( c$http$log_point == AFTER_REPLY_BODY ) 
			do_log(c);
		
	}
	
