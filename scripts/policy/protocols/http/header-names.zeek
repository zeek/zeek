##! Extract and include the header names used for each request in the HTTP
##! logging stream.  The headers in the logging stream will be stored in the
##! same order which they were seen on the wire.

@load base/protocols/http/main

module HTTP;

export {
	redef record Info += {
		## The vector of HTTP header names sent by the client.  No
		## header values are included here, just the header names.
		client_header_names:  vector of string &log &optional;

		## The vector of HTTP header names sent by the server.  No
		## header values are included here, just the header names.
		server_header_names:  vector of string &log &optional;
	};

	## A boolean value to determine if client header names are to be logged.
	option log_client_header_names = T;

	## A boolean value to determine if server header names are to be logged.
	option log_server_header_names = F;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( ! c?$http )
		return;

	if ( is_orig )
		{
		if ( log_client_header_names )
			{
			if ( ! c$http?$client_header_names )
				c$http$client_header_names = vector();
			c$http$client_header_names += name;
			}
		}
	else
		{
		if ( log_server_header_names )
			{
			if ( ! c$http?$server_header_names )
				c$http$server_header_names = vector();
			c$http$server_header_names += name;
			}
		}
	}
