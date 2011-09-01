##! This implements all of the additional information and geodata detections 
##! for SSH analysis.

@load base/frameworks/notice/main
@load base/protocols/ssh/main

module SSH;

export {
	redef enum Notice::Type += {
		## If an SSH login is seen to or from a "watched" country based on the
		## :bro:id:`SSH::watched_countries` variable then this notice will
		## be generated.
		Login_From_Watched_Country,
	};
	
	## The set of countries for which you'd like to throw notices upon 
	## successful login
	const watched_countries: set[string] = {"RO"} &redef;

	redef record Info += {
		## Add geographic data related to the "remote" host of the connection.
		remote_location: geo_location &log &optional;
	};
}

event SSH::heuristic_successful_login(c: connection) &priority=5
	{
	local location: geo_location;
	location = (c$ssh$direction == OUTBOUND) ? 
		lookup_location(c$id$resp_h) : lookup_location(c$id$orig_h);
	
	# Add the location data to the SSH record.
	c$ssh$remote_location = location;
	
	if ( location?$country_code && location$country_code in watched_countries )
		{
		NOTICE([$note=Login_From_Watched_Country,
		        $conn=c,
		        $msg=fmt("SSH login from watched country: %s", location$country_code)]);
		}
	}
