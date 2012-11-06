@load base/frameworks/intel
@load base/protocols/smtp
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

		if ( c$smtp?$x_originating_ip )
			Intel::seen([$host=c$smtp$x_originating_ip,
			             $conn=c,
			             $where=SMTP::IN_X_ORIGINATING_IP_HEADER]);

		if ( c$smtp?$mailfrom )
			Intel::seen([$str=c$smtp$mailfrom,
			             $str_type=Intel::EMAIL,
			             $conn=c,
			             $where=SMTP::IN_MAIL_FROM]);

		if ( c$smtp?$rcptto )
			{
			for ( rcptto in c$smtp$rcptto )
				{
				Intel::seen([$str=rcptto,
				             $str_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_RCPT_TO]);
				}
			}

		if ( c$smtp?$from )
			Intel::seen([$str=c$smtp$from,
			             $str_type=Intel::EMAIL,
			             $conn=c,
			             $where=SMTP::IN_FROM]);

		if ( c$smtp?$to )
			{
			for ( email_to in c$smtp$to )
				{
				Intel::seen([$str=email_to,
				             $str_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_TO]);
				}
			}

		if ( c$smtp?$reply_to )
			Intel::seen([$str=c$smtp$reply_to,
			             $str_type=Intel::EMAIL,
			             $conn=c,
			             $where=SMTP::IN_REPLY_TO]);
		}
	}
