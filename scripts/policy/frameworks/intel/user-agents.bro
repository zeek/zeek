@load base/frameworks/intel
@load ./where-locations

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( is_orig && name == "USER-AGENT" )
		Intel::seen([$str=value,
		             $str_type=Intel::USER_AGENT,
		             $conn=c,
		             $where=HTTP::IN_USER_AGENT_HEADER]);
	}

event mime_end_entity(c: connection)
	{
	if ( c?$smtp && c$smtp?$user_agent )
		Intel::seen([$str=c$smtp$user_agent,
		             $str_type=Intel::USER_AGENT,
		             $conn=c,
		             $where=SMTP::IN_HEADER]);
	}
