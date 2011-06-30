# $Id: http-entity.bro 6 2004-04-30 00:31:26Z jason $

# Counts entity_level.

module HTTP;

event http_begin_entity(c: connection, is_orig: bool)
	{
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);
	++msg$entity_level;
	}

event http_end_entity(c: connection, is_orig: bool)
	{
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);
	if ( msg$entity_level > 0 )
		--msg$entity_level;
	}
