##! Software identification and extraction for HTTP traffic.

@load base/frameworks/software

module HTTP;

export {
	redef enum Software::Type += {
		## Identifier for web servers in the software framework.
		SERVER,
		## Identifier for app servers in the software framework.
		APPSERVER,
		## Identifier for web browsers in the software framework.
		BROWSER,
	};

	## The pattern of HTTP User-Agents which you would like to ignore.
	option ignored_user_agents = /NO_DEFAULT/;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	if ( is_orig )
		{
		if ( name == "USER-AGENT" && ignored_user_agents !in value )
			Software::found(c$id, [$unparsed_version=value, $host=c$id$orig_h, $software_type=BROWSER]);
		}
	else
		{
		if ( name == "SERVER" )
			Software::found(c$id, [$unparsed_version=value, $host=c$id$resp_h, $host_p=c$id$resp_p, $software_type=SERVER]);
		else if ( name == "X-POWERED-BY" )
			Software::found(c$id, [$unparsed_version=value, $host=c$id$resp_h, $host_p=c$id$resp_p, $software_type=APPSERVER]);
		else if ( name == "MICROSOFTSHAREPOINTTEAMSERVICES" )
			{
			value = cat("SharePoint/", value);
			Software::found(c$id, [$unparsed_version=value, $host=c$id$resp_h, $host_p=c$id$resp_p, $software_type=APPSERVER]);
			}
		}
	}
