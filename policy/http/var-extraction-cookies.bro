## This script extracts and logs variables from cookies sent by clients

@load http/utils

module HTTP;

export {
	redef record State += {
		# TODO: This will change to be initialized to an empty vector when possible.
		cookie_vars: vector of string &optional &log;
	};
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	if ( !is_orig ) return;

	if ( name == "COOKIE" )
		c$http$cookie_vars = extract_keys(value, /;[[:blank:]]*/);
	}