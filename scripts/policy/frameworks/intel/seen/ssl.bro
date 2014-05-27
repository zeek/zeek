@load base/frameworks/intel
@load base/protocols/ssl
@load ./where-locations

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
	{
	if ( is_orig && c?$ssl && c$ssl?$server_name )
		Intel::seen([$indicator=c$ssl$server_name,
		             $indicator_type=Intel::DOMAIN,
		             $conn=c,
		             $where=SSL::IN_SERVER_NAME]);
	}
