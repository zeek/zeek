@load base/frameworks/intel
@load ./where-locations
@load base/utils/addrs

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( is_orig )
		{
		switch ( name ) 
			{
			case "HOST": 
			Intel::seen([$indicator=value,
			             $indicator_type=Intel::DOMAIN,
			             $conn=c,
			             $where=HTTP::IN_HOST_HEADER]);
			break;

			case "REFERER":
			Intel::seen([$indicator=sub(value, /^.*:\/\//, ""),
			             $indicator_type=Intel::URL,
			             $conn=c,
			             $where=HTTP::IN_REFERRER_HEADER]);
			break;

			case "X-FORWARDED-FOR":
			if ( is_valid_ip(value) )
				{
				local addrs = find_ip_addresses(value);
				for ( i in addrs )
					{
					Intel::seen([$host=to_addr(addrs[i]),
					             $indicator_type=Intel::ADDR,
					             $conn=c,
					             $where=HTTP::IN_X_FORWARDED_FOR_HEADER]);
					}
				}
			break;

			case "USER-AGENT":
			Intel::seen([$indicator=value,
			             $indicator_type=Intel::SOFTWARE,
			             $conn=c,
			             $where=HTTP::IN_USER_AGENT_HEADER]);
			break;
			}
		}
	}
