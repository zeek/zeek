##! Extract and include the headers used for each request in the log.

@load http/base

module HTTP;

redef record State += {
	headers:  vector of string &log &default=vector("");
};

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=4
	{
	if ( ! is_orig )
		return;
	
	c$http$headers[|c$http$headers|+1] = name;
	}