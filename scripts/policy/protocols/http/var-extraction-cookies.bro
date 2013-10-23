##! Extracts and logs variable names from cookies sent by clients.

@load base/protocols/http/main
@load base/protocols/http/utils

module HTTP;

redef record Info += {
	## Variable names extracted from all cookies.
	cookie_vars: vector of string &optional &log;
};

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	if ( is_orig && name == "COOKIE" )
		c$http$cookie_vars = extract_keys(value, /;[[:blank:]]*/);
	}
