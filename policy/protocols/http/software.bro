##! Software identification and extraction for HTTP traffic.

@load http/base
@load software

module HTTP;

export {
	redef enum Software::Type += {
		WEB_SERVER,
		WEB_APPSERVER,
		WEB_BROWSER,
		WEB_BROWSER_PLUGIN
	};

	## The pattern of HTTP User-Agents which you would like to ignore.
	const ignored_user_agents = /NO_DEFAULT/ &redef;
	
	## These are patterns to identify browser plugins (including toolbars)
	## based on the User-Agent header.
	const plugin_user_agents = /BingBar [0-9\.]*/                 ##< Bing toolbar
	                          | /GoogleToolbar [0-9\.]*;/ &redef; ##< Google toolbar
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	if ( is_orig )
		{
		if ( name == "USER-AGENT" && ignored_user_agents !in value )
			{
			local ua_type = WEB_BROWSER;
			if ( plugin_user_agents in value )
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
			Software::found(c$id, Software::parse(value, c$id$resp_h, WEB_SERVER));
		else if ( name == "X-POWERED-BY" )
			Software::found(c$id, Software::parse(value, c$id$resp_h, WEB_APPSERVER));
		}
	}