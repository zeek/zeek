# $Id: http-reply.bro 2694 2006-04-02 22:50:00Z vern $

@load http-request

module HTTP;

redef capture_filters += {
	["http-reply"] = "tcp src port 80 or tcp src port 8080 or tcp src port 8000"
};

redef process_HTTP_replies = T;

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	local s = lookup_http_request_stream(c);
	local msg = s$next_reply;

	init_http_message(msg);

	msg$initiated = T;
	msg$code = code;
	msg$reason = reason;
	}

function http_request_done(c: connection, stat: http_message_stat)
	{
	local s = lookup_http_request_stream(c);
	local msg = s$next_request;
	msg$initiated = F;
	}

function http_reply_done(c: connection, stat: http_message_stat)
	{
	local s = lookup_http_request_stream(c);
	local req_msg = s$next_request;
	local msg = s$next_reply;
	local req: string;
	local have_request = F;
	local log_it: bool;

	if ( s$num_pending_requests == 0 )
		{
		# Weird - reply w/o request - perhaps due to cold start?
		req = "<unknown request>";
		log_it = F;
		}
	else
		{
		local r = s$requests[s$first_pending_request];
		have_request = T;

		# Remove pending request.
		delete s$requests[s$first_pending_request];
		--s$num_pending_requests;
		++s$first_pending_request;

		req = fmt("%s %s", r$method, r$URI);
		log_it = r$log_it;
		}

	local req_rep =
		fmt("%s (%d \"%s\" [%d%s]%s)",
			req, msg$code, string_escape(msg$reason, "\""),
			stat$body_length,
			stat$interrupted ? " (interrupted)" : "",
			have_request ? fmt(" %s", req_msg$host) : "");

	# The following is a more verbose form:
# 	local req_rep =
# 		fmt("%s (%d \"%s\" [\"%s\", %d%s%s])",
# 			req, msg$code, msg$reason,
# 			msg$content_length, stat$body_length,
# 			stat$interrupted ? " (interrupted)" : "",
# 			stat$content_gap_length > 0 ?
# 				fmt(" (gap = %d bytes)", stat$content_gap_length) : "");

	if ( log_it )
		NOTICE([$note=HTTP_SensitiveURI, $conn=c,
			$method = r$method, $URL = r$URI,
			$n = msg$code,
			$msg = fmt("%s %s: %s",
				id_string(c$id), c$addl, req_rep)]);

	print http_log, fmt("%.6f %s %s", network_time(), s$id, req_rep);

	msg$initiated = F;
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( is_orig )
		http_request_done(c, stat);
	else
		http_reply_done(c, stat);
	}

@load http-entity
event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	# Only rewrite top-level headers.
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);

	if ( msg$entity_level == 1 )
		{
		if ( name == "CONTENT-LENGTH" )
			msg$content_length = value;

		else if ( is_orig && name == "HOST" )
			{ # suppress leading blank
			if ( /^ / in value )
				msg$host = sub_bytes(value, 2, -1);
			else
				msg$host = value;
			}
		}
	}
