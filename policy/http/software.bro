##! Software identification and extraction for HTTP traffic.

@load http/base
@load software

module HTTP;

redef enum Software::Type += {
	WEB_SERVER,
	WEB_BROWSER,
	WEB_BROWSER_PLUGIN,
};


export {
	## The pattern of HTTP User-Agents which you would like to ignore.
	const ignored_user_agents = /NO_DEFAULT/ &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	if ( is_orig )
		{
		if ( name == "USER-AGENT" && ignored_user_agents !in value )
			{
			local ua_type = WEB_BROWSER;
			if ( /^Java/ in value )
				ua_type = WEB_BROWSER_PLUGIN;
				
			Software::found(c$id, Software::parse(value, c$id$orig_h, ua_type));
			}
		else if ( name == "X-FLASH-VERSION" )
			{
			# Flash doesn't include it's name so we'll add it here since it 
			# simplifies the version parsing.
			value = cat("Flash/", value);
			local flash_version = Software::parse(value, c$id$orig_h, WEB_BROWSER_PLUGIN);
			Software::found(c$id, flash_version);
			}
		}
	else
		{
		if ( name == "SERVER" )
			{
			Software::found(c$id, Software::parse(value, c$id$resp_h, WEB_SERVER));
			}
		}
	}