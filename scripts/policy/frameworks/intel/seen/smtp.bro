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
			Intel::seen([$indicator=c$smtp$user_agent,
			             $indicator_type=Intel::SOFTWARE,
			             $conn=c,
			             $where=SMTP::IN_HEADER]);

		if ( c$smtp?$x_originating_ip )
			Intel::seen([$host=c$smtp$x_originating_ip,
			             $conn=c,
			             $where=SMTP::IN_X_ORIGINATING_IP_HEADER]);

		if ( c$smtp?$mailfrom )
			{
			local mailfromparts = split_n(c$smtp$mailfrom, /<.+>/, T, 1);
			if ( |mailfromparts| > 2 )
				{
				Intel::seen([$indicator=mailfromparts[2][1:-2],
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_MAIL_FROM]);
				}
			}

		if ( c$smtp?$rcptto )
			{
			for ( rcptto in c$smtp$rcptto )
				{
				local rcpttoparts = split_n(rcptto, /<.+>/, T, 1);
				if ( |rcpttoparts| > 2 )
					{
					Intel::seen([$indicator=rcpttoparts[2][1:-2],
					             $indicator_type=Intel::EMAIL,
					             $conn=c,
					             $where=SMTP::IN_RCPT_TO]);
					}
				}
			}

		if ( c$smtp?$from )
			{
			local fromparts = split_n(c$smtp$from, /<.+>/, T, 1);
			if ( |fromparts| > 2 )
				{
				Intel::seen([$indicator=fromparts[2][1:-2],
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_FROM]);
				}
			}

		if ( c$smtp?$to )
			{
			for ( email_to in c$smtp$to )
				{
				local toparts = split_n(email_to, /<.+>/, T, 1);
				if ( |toparts| > 2 )
					{
					Intel::seen([$indicator=toparts[2][1:-2],
					             $indicator_type=Intel::EMAIL,
					             $conn=c,
					             $where=SMTP::IN_TO]);
					}
				}
			}

		if ( c$smtp?$reply_to )
			{
			local replytoparts = split_n(c$smtp$reply_to, /<.+>/, T, 1);
			if ( |replytoparts| > 2 )
				{
				Intel::seen([$indicator=replytoparts[2][1:-2],
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_REPLY_TO]);
				}
			}
		}
	}
