@load base/utils/email
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
			Intel::seen([$indicator=c$smtp$mailfrom,
			             $indicator_type=Intel::EMAIL,
			             $conn=c,
			             $where=SMTP::IN_MAIL_FROM]);
			}

		if ( c$smtp?$rcptto )
			{
			for ( rcptto_addr in c$smtp$rcptto )
				{
				Intel::seen([$indicator=rcptto_addr,
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_RCPT_TO]);
				}
			}

		if ( c$smtp?$from )
			{
			for ( from_addr in extract_email_addrs_set(c$smtp$from) )
				{
				Intel::seen([$indicator=from_addr,
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_FROM]);
				}
			}

		if ( c$smtp?$to )
			{
			for ( email_to_addr in c$smtp$to )
				{
				Intel::seen([$indicator=extract_first_email_addr(email_to_addr),
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_TO]);
				}
			}

		if ( c$smtp?$cc )
			{
			for ( cc_addr in c$smtp$cc )
				{
				Intel::seen([$indicator=cc_addr,
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_CC]);
				}
			}

		if ( c$smtp?$reply_to )
			{
			Intel::seen([$indicator=c$smtp$reply_to,
			             $indicator_type=Intel::EMAIL,
			             $conn=c,
			             $where=SMTP::IN_REPLY_TO]);
			}
		}
	}
