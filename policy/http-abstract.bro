# $Id: http-abstract.bro 47 2004-06-11 07:26:32Z vern $

@load http
@load http-entity

module HTTP;

export {
	const abstract_max_length = 512 &redef;
}

redef http_entity_data_delivery_size = 4096;
redef include_HTTP_abstract = T;

function skip_abstract(c: connection, is_orig: bool, msg: http_message)
	{
	msg$skip_abstract = T;
	if ( ! process_HTTP_data )
		skip_http_entity_data(c, is_orig);
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string)
	{
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);

	if ( msg$entity_level == 1 && ty == "TEXT" )
		# Do not skip the body in this case.
		return;

	skip_abstract(c, is_orig, msg);
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);

	if ( msg$skip_abstract )
		return;

	local len = byte_len(data);
	if ( len > abstract_max_length )
		msg$abstract = sub_bytes(data, 1, abstract_max_length);
	else
		msg$abstract = data;

	skip_abstract(c, is_orig, msg);

	# print http_log, fmt("%.6f %s %s %d bytes: \"%s\"",
	#			network_time(), s$id,
	#			is_orig ? "=>" : "<=", byte_len(msg$abstract),
	#			msg$abstract);
	}
