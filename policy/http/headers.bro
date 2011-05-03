##! Extract and include the header keys used for each request in the log.

@load http/base

module HTTP;

redef record Info += {
	## The vector of HTTP headers.  No header values are included here, just
	## the header names.
	## TODO: with an empty vector as &default, the vector isn't coerced to the
	##       correct type.
	headers:  vector of string &log &optional;
};

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=4
	{
	if ( ! is_orig )
		return;
	
	if ( ! c$http?$headers )
		c$http$headers = vector();
	c$http$headers[|c$http$headers|] = name;
	}