
module HTTP;

export {
	redef enum Log::ID += { HTTP };

	## Indicate a type of attack or compromise in the record to be logged.
	type Tags: enum {
		EMPTY
	};
	
	## This setting changes if passwords used in Basic-Auth are captured or not.
	const default_capture_password = F &redef;
	
	type Info: record {
		ts:                      time     &log;
		uid:                     string   &log;
		id:                      conn_id  &log;
		## The verb used in the HTTP request (GET, POST, HEAD, etc.).
		method:                  string   &log &optional;
		## The value of the HOST header.
		host:                    string   &log &optional;
		## The URI used in the request.
		uri:                     string   &log &optional;
		## The value of the "referer" header.  The comment is deliberately
		## misspelled like the standard declares, but the name used here is
		## "referrer" spelled correctly.
		referrer:                string   &log &optional;
		## The value of the User-Agent header from the client.
		user_agent:              string   &log &optional;
		## The value of the Content-Length header from the client.
		request_content_length:  count    &log &optional;
		## The value of the Content-Length header from the server.
		response_content_length: count    &log &optional;
		## The status code returned by the server.
		status_code:             count    &log &optional;
		## The status message returned by the server.
		status_msg:              string   &log &optional;
		## The filename given in the Content-Disposition header
		## sent by the server.
		filename:                string   &log &optional;
		## This is a set of indicators of various attributes discovered and
		## related to a particular request/response pair.
		tags:                    set[Tags] &log;
		
		## The username if basic-auth is performed for the request.
		username:           string  &log &optional;
		## The password if basic-auth is performed for the request.
		password:           string  &log &optional;
		
		## This determines if the password will be captured for this request.
		capture_password:   bool &default=default_capture_password;
		
		## All of the headers that may indicate if the request was proxied.
		proxied:            set[string] &log &optional;
	};
	
	type State: record {
		pending:          table[count] of Info;
		current_response: count                &default=0;
		current_request:  count                &default=0;
	};
		
	## The list of HTTP headers typically used to indicate a proxied request.
	const proxy_headers: set[string] = {
		"FORWARDED",
		"X-FORWARDED-FOR",
		"X-FORWARDED-FROM",
		"CLIENT-IP",
		"VIA",
		"XROXY-CONNECTION",
		"PROXY-CONNECTION",
	} &redef;
	
	global log_http: event(rec: Info);
}

# Add the http state tracking fields to the connection record.
redef record connection += {
	http:        Info  &optional;
	http_state:  State &optional;
};

# Initialize the HTTP logging stream.
event bro_init() &priority=5
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
			c$http$request_content_length = extract_count(value);
			
		else if ( name == "USER-AGENT" )
			c$http$user_agent = value;
			
		else if ( name in proxy_headers )
				{
				if ( ! c$http?$proxied )
					c$http$proxied = set();
				add c$http$proxied[fmt("%s -> %s", name, value)];
				}

		else if ( name == "AUTHORIZATION" )
			{
			if ( /^[bB][aA][sS][iI][cC] / in value )
				{
				local userpass = decode_base64(sub(value, /[bB][aA][sS][iI][cC][[:blank:]]/, ""));
				local up = split(userpass, /:/);
				if ( |up| >= 2 )
					{
					c$http$username = up[1];
					if ( c$http$capture_password )
						c$http$password = up[2];
					}
				else
					{
					c$http$username = "<problem-decoding>";
					if ( c$http$capture_password )
						c$http$password = userpass;
					}
				}
			}
			
			
		}
	else # server headers
		{
		if ( name == "CONTENT-LENGTH" )
			c$http$response_content_length = extract_count(value);
		else if ( name == "CONTENT-DISPOSITION" &&
		          /[fF][iI][lL][eE][nN][aA][mM][eE]/ in value )
			c$http$filename = sub(value, /^.*[fF][iI][lL][eE][nN][aA][mM][eE]=/, "");
		}
	}
	
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = 5
	{
	set_state(c, F, is_orig);
	}
	
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = -5
	{
	# The reply body is done so we're ready to log.
	if ( ! is_orig )
		{
		Log::write(HTTP, c$http);
		delete c$http_state$pending[c$http_state$current_response];
		}
	}

event connection_state_remove(c: connection)
	{
	# Flush all pending but incomplete request/response pairs.
	if ( c?$http_state )
		{
		for ( r in c$http_state$pending )
			{
			Log::write(HTTP, c$http_state$pending[r]);
			}
		}
	}
	
