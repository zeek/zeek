@load base/frameworks/intel
@load base/protocols/ssl
@load ./where-locations

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	if ( is_orig && SSL::extensions[code] == "server_name" && 
	     c?$ssl && c$ssl?$server_name )
		Intel::seen([$indicator=c$ssl$server_name,
		             $indicator_type=Intel::DOMAIN,
		             $conn=c,
		             $where=SSL::IN_SERVER_NAME]);
	}
