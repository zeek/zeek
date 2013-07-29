@load base/frameworks/intel
@load ./where-locations

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( is_orig && name == "HOST" )
		Intel::seen([$indicator=value,
		             $indicator_type=Intel::DOMAIN,
		             $conn=c,
		             $where=HTTP::IN_HOST_HEADER]);
	}
