##! Detect and log web applications through the software framework.

@load base/frameworks/signatures
@load base/frameworks/software
@load base/protocols/http

@load-sigs ./detect-webapps.sig

module HTTP;

# Ignore the signatures used to match webapps
redef Signatures::ignored_ids += /^webapp-/;

export {
	redef enum Software::Type += {
		## Identifier for web applications in the software framework.
		WEB_APPLICATION,
	};

	redef record Software::Info += {
		## Most root URL where the software was discovered.
		url:   string &optional &log;
	};
}

event signature_match(state: signature_state, msg: string, data: string) &priority=5
	{
	if ( /^webapp-/ !in state$sig_id ) return;
	
	local c = state$conn;
	local si: Software::Info;
	si = [$name=msg, $unparsed_version=msg, $host=c$id$resp_h, $host_p=c$id$resp_p, $software_type=WEB_APPLICATION];
	si$url = build_url_http(c$http);
	if ( c$id$resp_h in Software::tracked &&
	     si$name in Software::tracked[c$id$resp_h] )
		{
		# If the new url is a substring of an existing, known url then let's
		# use that as the new url for the software.
		# PROBLEM: different version of the same software on the same server with a shared root path
		local is_substring = 0;
		if ( Software::tracked[c$id$resp_h][si$name]?$url &&
		     |si$url| <= |Software::tracked[c$id$resp_h][si$name]$url| )
			is_substring = strstr(Software::tracked[c$id$resp_h][si$name]$url, si$url);
		
		if ( is_substring == 1 )
			{
			Software::tracked[c$id$resp_h][si$name]$url = si$url;
			# Force the software to be logged because it indicates a URL
			# closer to the root of the site.
			si$force_log = T;
			}
		}
	
	Software::found(c$id, si);
	}
