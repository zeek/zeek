# $Id: http-body.bro 5230 2008-01-14 01:38:18Z vern $

# Counts length of data.
#
# If log_HTTP_data = T, it also outputs an abstract of data.

@load http

module HTTP;

redef process_HTTP_data = T;
redef log_HTTP_data = T;

export {
	# If the following is > 0, then when logging contents, they will be
	# truncated beyond this many bytes.
	global content_truncation_limit = 40 &redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);
	local len = byte_len(data);

	msg$data_length = msg$data_length + length;

	if ( log_HTTP_data )
		{
		local abstract: string;
		if ( content_truncation_limit > 0 &&
		     len > content_truncation_limit )
			abstract = cat(sub_bytes(data, 1, content_truncation_limit), "...");
		else
			abstract = data;

		print http_log, fmt("%.6f %s %s %d bytes: \"%s\"",
					network_time(), s$id,
					is_orig ? "=>" : "<=", length,
					abstract);
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);

	# This is for debugging purpose only
	if ( msg$data_length > 0 &&
	     stat$body_length != msg$data_length + stat$content_gap_length)
		{
		# This can happen for multipart messages with a
		# 'content-length' header, which is not required for multipart
		# messages.
		alarm fmt("length mismatch: %s %d %d %d",
			id_string(c$id), stat$body_length, msg$data_length,
			stat$content_gap_length);
		}
	}
