module SMTP;

export {
	## Places where it's suspicious for mail to originate from.
	##  requires all-capital, two character country codes (e.x. US)
	##  requires libGeoIP support built in.
	const suspicious_origination_countries: set[string] = {} &redef;
	const suspicious_origination_networks: set[subnet] = {} &redef;

	# This matches content in SMTP error messages that indicate some
	# block list doesn't like the connection/mail.
	const bl_error_messages = 
	    /spamhaus\.org\//
	  | /sophos\.com\/security\//
	  | /spamcop\.net\/bl/
	  | /cbl\.abuseat\.org\// 
	  | /sorbs\.net\// 
	  | /bsn\.borderware\.com\//
	  | /mail-abuse\.com\//
	  | /b\.barracudacentral\.com\//
	  | /psbl\.surriel\.com\// 
	  | /antispam\.imp\.ch\// 
	  | /dyndns\.com\/.*spam/
	  | /rbl\.knology\.net\//
	  | /intercept\.datapacket\.net\//
	  | /uceprotect\.net\//
	  | /hostkarma\.junkemailfilter\.com\// &redef;
}


#if ( c$smtp?$x_originating_ip )
#	{
#	ip = session$log$x_originating_ip;
#	loc = lookup_location(ip);
#	
#	if ( loc$country_code in suspicious_origination_countries ||
#		 ip in suspicious_origination_networks )
#		{
#		NOTICE([$note=SMTP_Suspicious_Origination,
#			    $msg=fmt("An email originated from %s (%s).", loc$country_code, ip),
#			    $sub=fmt("Subject: %s", session$log$subject),
#			    $conn=c]);
#		}
#	if ( session$log?$received_from_originating_ip &&
#	     session$log$received_from_originating_ip != session$log$x_originating_ip )
#		{
#		ip = session$log$received_from_originating_ip;
#		loc = lookup_location(ip);
#
#		if ( loc$country_code in suspicious_origination_countries ||
#			 ip in suspicious_origination_networks )
#			{
#			NOTICE([$note=SMTP_Suspicious_Origination,
#				    $msg=fmt("An email originated from %s (%s).", loc$country_code, ip),
#				    $sub=fmt("Subject: %s", session$log$subject),
#					$conn=c]);
#			}
#		}
#	}
#