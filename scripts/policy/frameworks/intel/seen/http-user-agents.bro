@load base/frameworks/intel
@load ./where-locations

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( is_orig && name == "USER-AGENT" )
		Intel::seen([$indicator=value,
		             $indicator_type=Intel::SOFTWARE,
		             $conn=c,
		             $where=HTTP::IN_USER_AGENT_HEADER]);
	}

