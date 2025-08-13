##! Extracts and logs variables from the requested URI in the default HTTP
##! logging stream.

@load base/protocols/http

module HTTP;

redef record Info += {
	## Variable names from the URI.
	uri_vars:    vector of string &optional &log;
};

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=2
	{
	local param_parts = split_string1(original_URI, /\?/);
	if ( |param_parts| > 1 )
		{
		c$http$uri_vars = extract_keys(param_parts[1], /&/);
		}
	}
