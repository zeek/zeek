@load base/frameworks/notice/main
@load base/protocols/smtp/main

module SMTP;

export {
	redef enum Notice::Type += {
		Suspicious_Origination
	};

	## Places where it's suspicious for mail to originate from represented
	## as all-capital, two character country codes (e.g., US).  It requires
	## Zeek to be built with GeoIP support.
	option suspicious_origination_countries: set[string] = {};
	option suspicious_origination_networks: set[subnet] = {};

}

event log_smtp(rec: Info)
	{
	local ip: addr;
	local loc: geo_location;
	if ( rec?$x_originating_ip )
		{
		ip = rec$x_originating_ip;
		loc = lookup_location(ip);

		if ( (loc?$country_code &&
			 loc$country_code in suspicious_origination_countries) ||
			 ip in suspicious_origination_networks )
			{
			NOTICE([$note=Suspicious_Origination,
			        $msg=fmt("An email originated from %s (%s).",
			                 loc?$country_code ? loc$country_code : "", ip),
			        $id=rec$id]);
			}
		}
	if ( rec?$path )
		{
		ip = rec$path[|rec$path|-1];
		loc = lookup_location(ip);

		if ( (loc?$country_code &&
			 loc$country_code in suspicious_origination_countries) ||
			 ip in suspicious_origination_networks )
			{
			NOTICE([$note=Suspicious_Origination,
			        $msg=fmt("Based up Received headers, email originated from %s (%s).", loc?$country_code ? loc$country_code : "", ip),
			        $id=rec$id]);
			}
		}
	}
