event new_connection(c: connection)
	{
	local originator_host: addr = c$id$orig_h;
	local responder_host: addr = c$id$resp_h;

	print fmt("Found connection between %s and %s", originator_host,
	    responder_host);
	}
