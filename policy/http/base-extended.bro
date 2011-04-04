## Add "extended" information to the base HTTP analysis.
module HTTP;

export {
	redef record State += {
		## The username if basic-auth is performed for the request.
		username:           string  &log &optional;
		## The password if basic-auth is performed for the request.
		password:           string  &log &optional;
		
		## All of the headers that may indicate if the request was proxied.
		proxied:            set[string] &log &optional;
	};
	
	## This setting changes if passwords used in Basic-Auth are captured or not.
	const capture_passwords = F &redef;
	
	## The list of HTTP headers typically used to indicate a proxied request.
	const proxy_headers: set[string] = {
		"HTTP-FORWARDED",
		"FORWARDED",
		"HTTP-X-FORWARDED-FOR",
		"X-FORWARDED-FOR",
		"HTTP-X-FORWARDED-FROM",
		"X-FORWARDED-FROM",
		"HTTP-CLIENT-IP",
		"CLIENT-IP",
		"HTTP-FROM",
		"FROM",
		"HTTP-VIA",
		"VIA",
		"HTTP-XROXY-CONNECTION",
		"XROXY-CONNECTION",
		"HTTP-PROXY-CONNECTION",
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
					if ( capture_passwords )
						c$http$password = up[2];
					}
				else
					{
					c$http$username = "<problem-decoding>";
					if ( capture_passwords )
						c$http$password = userpass;
					}
				}
			}
		}
	}
