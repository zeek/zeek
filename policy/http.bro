##! Yay, this is the new HTTP script

## Author: Seth Hall <seth@icir.org> - Inspired by the work many others.

@load functions
@load notice
@load software

module HTTP;

redef enum Log::ID += { HTTP };
redef enum Software::Type += {
	WEB_SERVER,
	WEB_BROWSER,
	WEB_BROWSER_PLUGIN,
};

export {
	type LogTags: enum {
		## Indicator of a URI based SQL injection attack.
		URI_SQLI,
		## Indicator of client body based SQL injection attack.  This is 
		## typically the body content of a POST request.
		POST_SQLI,
		## Indicator of a cookie based SQL injection attack.
		COOKIE_SQLI,
	};
	
	type Log: record {
		ts:                 time;
		id:                 conn_id;
		method:             string &default="";
		host:               string &default="";
		uri:                string &default="";
		referrer:           string &default="";
		user_agent:         string &default="";
		request_body_size:  count &default=0;
		response_body_size: count &default=0;
		status_code:        count &default=0;
		status_msg:         string &default="";
		username:           string &default="";
		password:           string &default="";
		## This is a set of indicators of various attributes discovered and
		## related to a particular request/response pair.
		tags:               set[LogTags];
		
		# TODO: I think I want this in a separate script.  Not sure I like it here.
		## All of the headers that may indicate if the request was proxied.
		proxied:            set[string];
		
		# Do this in a separate script.
		#post_vars:   vector of string;
		
		# Do these in a separate script.
		#mime_type:   string &default="";
		#generate_md5: bool &default=F;
		#md5: string &default="";
		#file_name: string; ##maybe if the header's there?
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
	
	type SessionInfo: record {
		log:              Log;
		#pending_requests: Request;
		log_point:        LogPoint &default=default_log_point;
	};

	## This regular expression is used to match URI based SQL injections
	const match_sql_injection_uri = 
		#  /[\?&][^[:blank:]\|]+?=[\-0-9%]+([[:blank:]]|\/\*.*?\*\/)*['"]?([[:blank:]]|\/\*.*?\*\/|\)?;)+([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])[^a-zA-Z&]/
		 /[\?&][^[:blank:]\|]+?=[\-0-9%]+([[:blank:]]|\/\*.*?\*\/)*['"]?([[:blank:]]|\/\*.*?\*\/|\)?;)+([oO][rR]|[aA][nN][dD])([[:blank:]]|\/\*.*?\*\/)+['"]?[^a-zA-Z&]+?=/
		| /[\?&][^[:blank:]]+?=[\-0-9%]*([[:blank:]]|\/\*.*?\*\/)*['"]([[:blank:]]|\/\*.*?\*\/)*(\-|\+|\|\|)([[:blank:]]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\|]+?=([[:blank:]]|\/\*.*?\*\/)*['"]([[:blank:]]|\/\*.*?\*\/|;)*([oO][rR]|[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT]|\()[^a-zA-Z&]/
		| /[\?&][^[:blank:]]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/ &redef;

	## The list of HTTP headers typically used to indicate a proxied request.
	const proxy_headers: set[string] = {
		"HTTP-FORWARDED",
		"FORWARDED",
		"HTTP-X-FORWARDED-FOR",
		"X-FORWARDED-FOR",
		"HTTP-X-FORWARDED-FROM",
		"X-FORWARDED-FROM",
		"HTTP-CLIENT-IP",
		"CLIENT-IP",
		"HTTP-FROM",
		"FROM",
		"HTTP-VIA",
		"VIA",
		"HTTP-XROXY-CONNECTION",
		"XROXY-CONNECTION",
		"HTTP-PROXY-CONNECTION",
		"PROXY-CONNECTION",
	} &redef;

	## List of all active HTTP session indexed by conn_id.
	global active_conns: table[conn_id] of SessionInfo &read_expire=5mins;
	
}

event bro_init()
	{
	Log::create_stream("HTTP", "HTTP::Log");
	Log::add_default_filter("HTTP");
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

function new_http_log(id: conn_id): Log
	{
	local tags: set[LogTags] = set();
	local proxied: set[string] = set();
	local log: Log = [$ts=network_time(), $id=id, $tags=tags, $proxied=proxied,
	# TODO: some bug with record default initialization
	$user_agent="", $request_body_size=0, $response_body_size=0, $status_code=0, $status_msg="", $username="", $password="", $referrer="", $host=""
	];
	return log;
	}

function get_http_session(id: conn_id): SessionInfo
	{
	if ( id in active_conns )
		return active_conns[id];
	else
		{
		local info: SessionInfo;
		info$log = new_http_log(id);
		active_conns[id] = info;
		return info;
		}
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=1
	{
	#print fmt("REQUEST: %s %s", method, original_URI);
	local sess = get_http_session(c$id);
	
	sess$log$method = method;
	sess$log$uri = unescaped_URI;
	
	if ( match_sql_injection_uri in unescaped_URI )
		add sess$log$tags[URI_SQLI];
	}
	
event http_reply(c: connection, version: string, code: count, reason: string) &priority=1
	{
	#print fmt("REPLY: %s", code);
	local sess = get_http_session(c$id);
	
	sess$log$status_code = code;
	sess$log$status_msg = reason;
	}
	
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=1
	{
	local sess = get_http_session(c$id);
	
	if ( is_orig ) # client headers
		{
		if ( name == "REFERER" )
			sess$log$referrer = value;

		else if ( name == "HOST" )
			sess$log$host = value;
		
		else if ( name == "CONTENT-LENGTH" )
			sess$log$request_body_size = to_count(value);
			
		else if ( name == "USER-AGENT" )
			{
			sess$log$user_agent = value;
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
		
		else if ( name in proxy_headers )
			add sess$log$proxied[fmt("%s -> %s", name, value)];

		else if ( name == "AUTHORIZATION" )
			{
			if ( /^[bB][aA][sS][iI][cC] / in value )
				{
				local userpass = decode_base64(sub(value, /[bB][aA][sS][iI][cC][[:blank:]]/, ""));
				local up = split(userpass, /:/);
				if ( |up| >= 2 )
					{
					sess$log$username = up[1];
					sess$log$password = up[2];
					}
				else
					{
					sess$log$username = "<problem-decoding>";
					sess$log$password = userpass;
					}
				}
			}
		}
	else # server headers
		{
		if ( name == "SERVER" )
			{
			local si = Software::default_parse(value, c$id$resp_h, WEB_SERVER);
			Software::found(c, si);
			}
		else if ( name == "CONTENT-LENGTH" )
			sess$log$response_body_size = to_count(value);
		}
	}
	
event http_begin_entity(c: connection, is_orig: bool) &priority=1
	{
	local sess = get_http_session(c$id);
	
	if ( is_orig )
		if ( sess$log_point == AFTER_REQUEST ) 
			Log::write("HTTP", sess$log);
	else
		if ( sess$log_point == AFTER_REQUEST ) 
			Log::write("HTTP", sess$log);
	}
	
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=1
	{
	local sess = get_http_session(c$id);
	
	if ( is_orig )
		if ( sess$log_point == AFTER_REQUEST_BODY ) 
			Log::write("HTTP", sess$log);
	else
		if ( sess$log_point == AFTER_REPLY_BODY ) 
			Log::write("HTTP", sess$log);
		
	}
	
