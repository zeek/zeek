@load base/frameworks/intel
@load base/protocols/smtp
@load ./where-locations

# Extract mail addresses out of address specifications conforming RFC 5322
function extract_mail_addrs(str: string) : set[string]
	{
	local raw_addrs = find_all(str, /(^|[<,:[:blank:]])[^<,:[:blank:]@]+"@"[^>,;[:blank:]]+([>,;[:blank:]]|$)/);
	local addrs: set[string];

	for ( raw_addr in raw_addrs )
		add addrs[gsub(raw_addr, /[<>,:;[:blank:]]/, "")];

	return addrs;
	}


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
			local mailfrom_addrs = extract_mail_addrs(c$smtp$mailfrom);
			for ( mailfrom_addr in mailfrom_addrs )
				{
				Intel::seen([$indicator=mailfrom_addr,
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_MAIL_FROM]);
				}
			}

		if ( c$smtp?$rcptto )
			{
			for ( rcptto in c$smtp$rcptto )
				{
				local rcptto_addrs = extract_mail_addrs(rcptto);
				for ( rcptto_addr in rcptto_addrs )
					{
					Intel::seen([$indicator=rcptto_addr,
					             $indicator_type=Intel::EMAIL,
					             $conn=c,
					             $where=SMTP::IN_RCPT_TO]);
					}
				}
			}

		if ( c$smtp?$from )
			{
			local from_addrs = extract_mail_addrs(c$smtp$from);
			for ( from_addr in from_addrs )
				{
				Intel::seen([$indicator=from_addr,
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_FROM]);
				}
			}

		if ( c$smtp?$to )
			{
			for ( email_to in c$smtp$to )
				{
				local email_to_addrs = extract_mail_addrs(email_to);
				for ( email_to_addr in email_to_addrs )
					{
					Intel::seen([$indicator=email_to_addr,
					             $indicator_type=Intel::EMAIL,
					             $conn=c,
					             $where=SMTP::IN_TO]);
					}
				}
			}

		if ( c$smtp?$reply_to )
			{
			local replyto_addrs = extract_mail_addrs(c$smtp$reply_to);
			for ( replyto_addr in replyto_addrs )
				{
				Intel::seen([$indicator=replyto_addr,
				             $indicator_type=Intel::EMAIL,
				             $conn=c,
				             $where=SMTP::IN_REPLY_TO]);
				}
			}
		}
	}
