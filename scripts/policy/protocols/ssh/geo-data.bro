##! Geodata based detections for SSH analysis.

@load base/frameworks/notice
@load base/protocols/ssh

module SSH;

export {
	redef enum Notice::Type += {
		## If an SSH login is seen to or from a "watched" country based
		## on the :bro:id:`SSH::watched_countries` variable then this
		## notice will be generated.
		Watched_Country_Login,
	};
	
	redef record Info += {
		## Add geographic data related to the "remote" host of the
		## connection.
		remote_location: geo_location &log &optional;
	};
	
	## The set of countries for which you'd like to generate notices upon 
	## successful login.
	const watched_countries: set[string] = {"RO"} &redef;
}

function get_location(c: connection): geo_location
	{
	local lookup_ip = (c$ssh$direction == OUTBOUND) ? c$id$resp_h : c$id$orig_h;
	return lookup_location(lookup_ip);
	}

event SSH::heuristic_successful_login(c: connection) &priority=5
	{
	# Add the location data to the SSH record.
	c$ssh$remote_location = get_location(c);
	
	if ( c$ssh$remote_location?$country_code && c$ssh$remote_location$country_code in watched_countries )
		{
		NOTICE([$note=Watched_Country_Login,
		        $conn=c,
		        $msg=fmt("SSH login %s watched country: %s", 
		                 (c$ssh$direction == OUTBOUND) ? "to" : "from", 
		                 c$ssh$remote_location$country_code)]);
		}
	}

event SSH::heuristic_failed_login(c: connection) &priority=5
	{
	# Add the location data to the SSH record.
	c$ssh$remote_location = get_location(c);
	}
