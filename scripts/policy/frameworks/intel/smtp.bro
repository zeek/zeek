@load base/frameworks/intel
@load ./where-locations

event mime_end_entity(c: connection)
	{
	if ( c?$smtp )
		{
		if ( c$smtp?$path )
			{
			local path = c$smtp$path;
			for ( i in path )
				{
				Intel::seen([$host=path[i],
				             $conn=c,
				             $where=SMTP::IN_RECEIVED_HEADER]);
				}
			}
		
		if ( c$smtp?$user_agent )
			Intel::seen([$str=c$smtp$user_agent,
			             $str_type=Intel::USER_AGENT,
			             $conn=c,
			             $where=SMTP::IN_HEADER]);
		}
	}
