##! This script is meant to answer the following questions...
##!   "How many unique 'MAIL FROM' addresses are being used by local mail servers per hour?"
##!   "How much mail is being sent from each local mail server per hour?"

@load base/frameworks/metrics

module SMTPMetrics;

export {
	## Define the break intervals for all of the metrics collected and logged by this script.
	const breaks = 1hr &redef;
}

event bro_init() &priority=5
	{
	Metrics::add_filter("smtp.mailfrom", [$pred(index: Metrics::Index) = { 
	                                      	return addr_matches_host(index$host, LOCAL_HOSTS); }, 
	                                      $break_interval=breaks]);
	Metrics::add_filter("smtp.messages", [$pred(index: Metrics::Index) = { 
	                                      	return addr_matches_host(index$host, LOCAL_HOSTS); }, 
	                                      $break_interval=breaks]);
	}

event SMTP::log_smtp(rec: SMTP::Info)
	{
	Metrics::add_data("smtp.messages", [$host=rec$id$orig_h], 1);
	
	if ( rec?$mailfrom )
		Metrics::add_unique("smtp.mailfrom", [$host=rec$id$orig_h], rec$mailfrom);
	}


