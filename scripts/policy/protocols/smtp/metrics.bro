##! This script is meant to answer the following questions...
##!   "How many unique 'MAIL FROM' addresses are being used by local mail servers per hour?"
##!   "How much mail is being sent from each local mail server per hour?"

@load base/protocols/smtp
@load base/frameworks/measurement
@load base/utils/site
@load base/utils/directions-and-hosts

module SMTPMetrics;

export {
	## Define the break intervals for all of the metrics collected and logged by this script.
	const breaks=1hr &redef;
}

event bro_init() &priority=5
	{
	Metrics::add_filter("smtp.mailfrom", [$every=breaks,
	                                      $measure=set(Metrics::SUM),
	                                      $pred(index: Metrics::Index, data: Metrics::DataPoint) = { 
	                                      	return addr_matches_host(index$host, LOCAL_HOSTS); 
	                                      }]);
	Metrics::add_filter("smtp.messages", [$every=breaks,
	                                      $measure=set(Metrics::SUM),
	                                      $pred(index: Metrics::Index, data: Metrics::DataPoint) = { 
	                                      	return addr_matches_host(index$host, LOCAL_HOSTS); 
	                                      }]);
	}

event SMTP::log_smtp(rec: SMTP::Info)
	{
	Metrics::add_data("smtp.messages", [$host=rec$id$orig_h], [$num=1]);
	
	if ( rec?$mailfrom )
		Metrics::add_data("smtp.mailfrom", [$host=rec$id$orig_h], [$str=rec$mailfrom]);
	}
