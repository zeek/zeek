@load http

module HTTP;

export {
	redef enum Notice += {
		PasswordFullFetch,	# they got back the whole thing
		PasswordShadowFetch,	# they got back a shadowed version
	};

	# Pattern to search for in replies indicating that a full password
	# file was returned.
	const full_fetch =
		/[[:alnum:]]+\:[[:alnum:]]+\:[[:digit:]]+\:[[:digit:]]+\:/
	&redef;

	# Same, but indicating a shadow password file was returned.
	const shadow_fetch =
		/[[:alnum:]]+\:\*\:[[:digit:]]+\:[[:digit:]]+\:/
	&redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	local s = lookup_http_request_stream(c);
	local n = s$first_pending_request;
	if ( n !in s$requests )
		return;

	local req = s$requests[n];
	local passwd_request = req$passwd_req;
	if ( ! passwd_request )
		return;

	if ( full_fetch in data )
		NOTICE([$note=PasswordFullFetch,
			$conn=c, $method=req$method, $URL=req$URI,
			$msg=fmt("%s %s: %s %s", id_string(c$id), c$addl,
					req$method, req$URI)]);
	else if ( shadow_fetch in data )
		NOTICE([$note=PasswordShadowFetch,
			$conn=c, $method=req$method, $URL=req$URI,
			$msg=fmt("%s %s: %s %s", id_string(c$id), c$addl,
					req$method, req$URI)]);
	}
