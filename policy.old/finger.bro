# $Id: finger.bro 4758 2007-08-10 06:49:23Z vern $

module Finger;

export {
	const hot_names = {
		"root", "lp", "uucp", "nuucp", "demos", "operator", "sync",
		"r00t", "tutor", "tour", "admin", "system", "guest", "visitor",
		"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
	} &redef;

	const max_finger_request_len = 80 &redef;
}

redef capture_filters += { ["finger"] = "port finger" };

# DPM configuration.
global finger_ports = { 79/tcp } &redef;
redef dpd_config += { [ANALYZER_FINGER] = [$ports = finger_ports] };

function public_user(user: string): bool
	{
	return T;
	}

function authorized_client(host: addr): bool
	{
	return T;
	}

event finger_request(c: connection, full: bool, username: string, hostname: string)
	{
	local id = c$id;
	local request: string;

	if ( hostname != "" )
		request = cat(username, "@", hostname);
	else
		request = username;

	if ( byte_len(request) > max_finger_request_len )
		{
		request = fmt("%s...", sub_bytes(request, 1, max_finger_request_len));
		++c$hot;
		}

	if ( hostname != "" )
		++c$hot;

	if ( username in hot_names )
		++c$hot;

	local req = request == "" ? "ALL" : fmt("\"%s\"", request);

	if ( full )
		req = fmt("%s (/W)", req);

	if ( c$addl != "" )
		# This is an additional request.
		req = fmt("(%s)", req);

	append_addl_marker(c, req, " *");
	}

function is_finger_conn(c: connection): bool
	{
	return c$id$resp_p == finger;
	}

