##! Detect browser plugins as they leak through requests to Omniture
##! advertising servers.

@load base/protocols/http
@load base/frameworks/software

module HTTP;

export {
	redef record Info += {
		## Indicates if the server is an omniture advertising server.
		omniture: bool &default=F;
		## The unparsed Flash version, if detected.
		flash_version: string &optional;
	};

	redef enum Software::Type += {
		## Identifier for browser plugins in the software framework.
		BROWSER_PLUGIN
	};
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( is_orig )
		{
		switch ( name )
			{
			case "X-FLASH-VERSION":
				# Flash doesn't include it's name so we'll add it here since it
				# simplifies the version parsing.
				c$http$flash_version = cat("Flash/", value);
				break;

			case "X-REQUESTED-WITH":
				# This header is usually used to indicate AJAX requests (XMLHttpRequest),
				# but Chrome uses this header also to indicate the use of Flash.
				if ( /Flash/ in value )
					c$http$flash_version = value;
				break;
			}
		}
	else
		{
		# Find if the server is Omniture
		if ( name == "SERVER" && /^Omniture/ in value )
			c$http$omniture = T;
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	# If a Flash was detected, it has to be logged considering the user agent.
	if ( is_orig && c$http?$flash_version )
		{
		# AdobeAIR contains a separate Flash, which should be emphasized.
		# Note: We assume that the user agent header was not reset by the app.
		if( c$http?$user_agent )
			{
			if ( /AdobeAIR/ in c$http$user_agent )
				c$http$flash_version = cat("AdobeAIR-", c$http$flash_version);
			}

		Software::found(c$id, [$unparsed_version=c$http$flash_version, $host=c$id$orig_h, $software_type=BROWSER_PLUGIN]);
		}
	}

event log_http(rec: Info)
	{
	# We only want to inspect requests that were sent to omniture advertising
	# servers.
	if ( rec$omniture && rec?$uri )
		{
		# We do {5,} because sometimes we see p=6 in the urls.
		local parts = split_string_n(rec$uri, /&p=([^&]{5,});&/, T, 1);
		if ( 1 in parts )
			{
			# We do sub_bytes here just to remove the extra extracted
			# characters from the regex split above.
			local sw = sub_bytes(parts[1], 4, |parts[1]|-5);
			local plugins = split_string(sw, /[[:blank:]]*;[[:blank:]]*/);

			for ( i in plugins )
				Software::found(rec$id, [$unparsed_version=plugins[i], $host=rec$id$orig_h, $software_type=BROWSER_PLUGIN]);
			}
		}
	}
