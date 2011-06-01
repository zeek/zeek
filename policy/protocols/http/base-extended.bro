##! Add "extended" information to the base HTTP analysis.

@load http/base

module HTTP;

export {
	## This setting changes if passwords used in Basic-Auth are captured or not.
	const default_capture_password = F &redef;

	redef record Info += {
		## The username if basic-auth is performed for the request.
		username:           string  &log &optional;
		## The password if basic-auth is performed for the request.
		password:           string  &log &optional;
		
		## This determines if the password will be captured for this request.
		capture_password:   bool &default=default_capture_password;
		
		## All of the headers that may indicate if the request was proxied.
		proxied:            set[string] &log &optional;
	};
	
	## The list of HTTP headers typically used to indicate a proxied request.
	const proxy_headers: set[string] = {
		"FORWARDED",
		"X-FORWARDED-FOR",
		"X-FORWARDED-FROM",
		"CLIENT-IP",
		"FROM",
		"VIA",
		"XROXY-CONNECTION",
		"PROXY-CONNECTION",
	} &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	if ( is_orig ) # client headers
		{
		if ( name in proxy_headers )
			{
			if ( ! c$http?$proxied )
				c$http$proxied = set();
			add c$http$proxied[fmt("%s -> %s", name, value)];
			}
			
		else if ( name == "AUTHORIZATION" )
			{
			if ( /^[bB][aA][sS][iI][cC] / in value )
				{
				local userpass = decode_base64(sub(value, /[bB][aA][sS][iI][cC][[:blank:]]/, ""));
				local up = split(userpass, /:/);
				if ( |up| >= 2 )
					{
					c$http$username = up[1];
					if ( c$http$capture_password )
						c$http$password = up[2];
					}
				else
					{
					c$http$username = "<problem-decoding>";
					if ( c$http$capture_password )
						c$http$password = userpass;
					}
				}
			}
		}
	}
