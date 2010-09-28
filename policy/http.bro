# $Id: http.bro 6726 2009-06-07 22:09:55Z vern $

@load notice
@load site
@load conn-id

module HTTP;

export {
	redef enum Notice += {
		HTTP_SensitiveURI,	# sensitive URI in GET/POST/HEAD
	};
}

# DPM configuration.
global http_ports = {
	80/tcp, 81/tcp, 631/tcp, 1080/tcp, 3138/tcp,
	8000/tcp, 8080/tcp, 8888/tcp,
};
redef dpd_config += { [ANALYZER_HTTP] = [$ports = http_ports] };
redef dpd_config += { [ANALYZER_HTTP_BINPAC] = [$ports = http_ports] };

# HTTP processing options.
export {
	const process_HTTP_replies = F &redef;
	const process_HTTP_data = F &redef;
	const include_HTTP_abstract = F &redef;
	const log_HTTP_data = F &redef;
}

type http_pending_request: record {
	method: string;
	URI: string;
	log_it: bool;

	# Whether we determined it's an attempted passwd file fetch.
	passwd_req: bool;
};

# Eventually we will combine http_pending_request and http_message.

type http_message: record {
	initiated: bool;
	code: count;		# for HTTP reply message
	reason: string;		# for HTTP reply message
	entity_level: count;	# depth of enclosing MIME entities
	data_length: count;	# actual length of data delivered
	content_length: string;	# length specified in CONTENT-LENGTH header
	header_slot: count;	# rewrite slot at the end of headers
	abstract: string;	# data abstract
	skip_abstract: bool;	# to skip abstract for certain content types
	host: string;		# host indicated in Host header
};

type http_pending_request_stream: record {
	# Number of first pending request.
	first_pending_request: count &default = 0;

	# Total number of pending requests.
	num_pending_requests: count &default = 0;

	# Indexed from [first_pending_request ..
	#		(first_pending_request + num_pending_requests - 1)]
	requests: table[count] of http_pending_request;

	next_request: http_message; 	# the on-going request
	next_reply: http_message;	# the on-going reply

	# len_next_reply: count;	# 0 means unspecified
	# len_next_request: count;

	id: string;	# repeated from http_session_info, for convenience
};

type http_session_info: record {
	id: string;
 	request_stream: http_pending_request_stream;
};

const http_log = open_log_file("http") &redef;

# Called when an HTTP session times out.
global expire_http_session:
	function(t: table[conn_id] of http_session_info, id: conn_id)
		: interval;

export {
	# Indexed by conn_id.
	# (Exported so that we can define a timeout on it.)
	global http_sessions: table[conn_id] of http_session_info
			&expire_func = expire_http_session
			&read_expire = 15 min;
}

global http_session_id = 0;

function init_http_message(msg: http_message)
	{
	msg$initiated = F;
	msg$code = 0;
	msg$reason = "";
	msg$entity_level = 0;
	msg$data_length = 0;
	msg$content_length = "";
	msg$header_slot = 0;
	msg$abstract = "";
	msg$skip_abstract = F;
	msg$host = "";
	}

function new_http_message(): http_message
	{
	local msg: http_message;
	init_http_message(msg);
	return msg;
	}

function new_http_session(c: connection): http_session_info
	{
	local session = c$id;
	local new_id = ++http_session_id;

	local info: http_session_info;
	info$id = fmt("%%%s", prefixed_id(new_id));

	local rs: http_pending_request_stream;

	rs$first_pending_request = 1;
	rs$num_pending_requests = 0;
	rs$id = info$id;

	rs$next_request = new_http_message();
	rs$next_reply = new_http_message();
	rs$requests = table();

	info$request_stream = rs;

	http_sessions[session] = info;

	print http_log, fmt("%.6f %s start %s:%d > %s:%d", network_time(),
				info$id, c$id$orig_h,
				c$id$orig_p, c$id$resp_h, c$id$resp_p);

	return info;
	}

function lookup_http_session(c: connection): http_session_info
	{
	local s: http_session_info;
	local id = c$id;

	s = id in http_sessions ? http_sessions[id] : new_http_session(c);

	append_addl(c, s$id);

	return s;
	}

function lookup_http_request_stream(c: connection): http_pending_request_stream
	{
	local s = lookup_http_session(c);

	return s$request_stream;
	}

function get_http_message(s: http_pending_request_stream, is_orig: bool): http_message
	{
	return is_orig ? s$next_request : s$next_reply;
	}

function finish_stream(session: conn_id, id: string,
			rs: http_pending_request_stream)
	{
	### We really want to do this in sequential order, not table order.
	for ( i in rs$requests )
		{
		local req = rs$requests[i];

		if ( req$log_it )
			NOTICE([$note=HTTP_SensitiveURI,
				$src=session$orig_h, $dst=session$resp_h,
				$URL=req$URI,
				$method=req$method,
				$msg=fmt("%s:%d -> %s:%d %s: <no reply>",
					session$orig_h, session$orig_p,
					session$resp_h, session$resp_p, id)]);

		local msg = fmt("%s %s <no reply>", req$method, req$URI);
		print http_log, fmt("%.6f %s %s", network_time(), rs$id, msg);
		}
	}

event connection_state_remove(c: connection)
	{
	local id = c$id;

	if ( id !in http_sessions )
		return;

	local s = http_sessions[id];
	finish_stream(id, s$id, s$request_stream);
	delete http_sessions[c$id];
	}

function expire_http_session(t: table[conn_id] of http_session_info,
				id: conn_id): interval
	{
	### FIXME: not really clear that we need this function at all ...
	#
	# One would think that connection_state_remove() already takes care
	# of everything.  However, without this expire-handler, some requests
	# don't show up with the test-suite (but haven't reproduced with
	# smaller traces) - Robin.

	local s = http_sessions[id];
	finish_stream(id, s$id, s$request_stream);
	return 0 sec;
	}

# event connection_timeout(c: connection)
# 	{
# 	if ( ! maintain_http_sessions )
# 		{
# 		local id = c$id;
# 		if ( [id$orig_h, id$resp_h] in http_sessions )
# 			delete http_sessions[id$orig_h, id$resp_h];
# 		}
# 	}

# event http_stats(c: connection, stats: http_stats_rec)
# 	{
# 	if ( stats$num_requests == 0 && stats$num_replies == 0 )
# 		return;
#
# 	c$addl = fmt("%s (%d v%.1f v%.1f)", c$addl, stats$num_requests, stats$request_version, stats$reply_version);
# 	}
