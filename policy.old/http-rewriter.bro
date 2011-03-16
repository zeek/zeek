# $Id: http-rewriter.bro 416 2004-09-17 03:52:28Z vern $

# We can't do HTTP rewriting unless we process everything in the connection.
@load http-reply
@load http-entity

module HTTP;

redef rewriting_http_trace = T;
redef http_entity_data_delivery_size = 4096;

const rewrite_header_in_position = F;

event http_request(c: connection, method: string,
		   original_URI: string, unescaped_URI: string, version: string)
	{
	if ( rewriting_trace() )
		rewrite_http_request(c, method, original_URI, version);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( rewriting_trace() )
		rewrite_http_reply(c, version, code, reason);
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ! rewriting_trace() )
		return;

	# Only rewrite top-level headers.
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);

	if ( msg$entity_level == 1 )
		{
		if ( name == "CONTENT-LENGTH" )
			{
			if ( rewrite_header_in_position )
				{
				local p = current_packet(c);
				if ( p$is_orig == is_orig )
					{
					# local s = lookup_http_request_stream(c);
					# local msg = get_http_message(s, is_orig);
					if ( msg$header_slot == 0 )
						msg$header_slot = reserve_rewrite_slot(c);
					}
				else
					print fmt("cannot reserve a slot at %.6f", network_time());
				}
			# rewrite_http_header(c, is_orig,
			#		"X-Original-Content-Length", value);
			}

		else if ( name == "TRANSFER-ENCODING" )
			rewrite_http_header(c, is_orig,
					"X-Original-Transfer-Encoding", value);

		else
			rewrite_http_header(c, is_orig, name, value);
		}
	}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	if ( ! rewriting_trace() )
		return;

	if ( rewrite_header_in_position )
		{
		local p = current_packet(c);
		if ( p$is_orig == is_orig )
			{
			local s = lookup_http_request_stream(c);
			local msg = get_http_message(s, is_orig);
			if ( msg$header_slot == 0 )
				msg$header_slot = reserve_rewrite_slot(c);
			}
		else
			print fmt("cannot reserve a slot at %.6f", network_time());

	      # An empty line to mark the end of headers.
	      rewrite_http_data(c, is_orig, "\r\n");
	      }
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( ! rewriting_trace() )
		return;

	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);
	local data_length = 0;

	if ( stat$interrupted )
		{
		print http_log,
			fmt("%.6f %s message interrupted at length=%d \"%s\"",
				network_time(), id_string(c$id),
				stat$body_length, stat$finish_msg);
		}

	if ( msg$header_slot > 0 )
		seek_rewrite_slot(c, msg$header_slot);

	if ( ! is_orig || stat$body_length > 0 )
		{
		if ( include_HTTP_abstract )
			data_length = byte_len(msg$abstract);

		data_length = data_length + stat$content_gap_length;

		rewrite_http_header(c, is_orig, "Content-Length",
					fmt(" %d", data_length));
		}

	rewrite_http_header(c, is_orig, "X-Actual-Data-Length",
				fmt(" %d; gap=%d, content-length=%s",
					stat$body_length,
					stat$content_gap_length,
					msg$content_length));
	if ( msg$header_slot > 0 )
		{
		release_rewrite_slot(c, msg$header_slot);
		msg$header_slot = 0;
		}

	if ( ! rewrite_header_in_position )
		# An empty line to mark the end of headers.
		rewrite_http_data(c, is_orig, "\r\n");

	if ( data_length > 0 )
		rewrite_http_data(c, is_orig, msg$abstract);
	}
