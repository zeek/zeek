##! Extract and include the header names used for each request in the HTTP
##! logging stream.  The headers in the logging stream will be stored in the
##! same order which they were seen on the wire.

@load base/protocols/http/main

module HTTP;

export {
	redef record Info += {
		## The vector of HTTP headers.  No header values are included here, just
		## the header names.
		headers:  vector of string &log &optional;
	};
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( ! is_orig || ! c?$http )
		return;
	
	if ( ! c$http?$headers )
		c$http$headers = vector();
	c$http$headers[|c$http$headers|] = name;
	}
