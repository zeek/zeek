##! Provides an example of using the metrics framework to collect the number
##! of times a specific server name indicator value is seen in SSL session
##! establishments.  Names ending in google.com are being filtered out as an
##! example of the predicate based filtering in metrics filters.

@load base/frameworks/measurement
@load base/protocols/ssl

event bro_init()
	{
	Metrics::add_filter("ssl.by_servername", 
		[$name="no-google-ssl-servers",
		 $every=10secs, $measure=set(Metrics::SUM),
		 $pred(index: Metrics::Index, data: Metrics::DataPoint) = { 
		    return (/google\.com$/ !in index$str); 
		 }]);
	}

event SSL::log_ssl(rec: SSL::Info)
	{
	if ( rec?$server_name )
		Metrics::add_data("ssl.by_servername", [$str=rec$server_name], [$num=1]);
	}
