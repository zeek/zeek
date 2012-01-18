##! Provides an example of using the metrics framework to collect the number
##! of times a specific server name indicator value is seen in SSL session
##! establishments.  Names ending in google.com are being filtered out as an
##! example of the predicate based filtering in metrics filters.

@load base/frameworks/metrics
@load base/protocols/ssl

redef enum Metrics::ID += {
	SSL_SERVERNAME,
};

event bro_init()
	{
	Metrics::add_filter(SSL_SERVERNAME, 
		[$name="no-google-ssl-servers",
		 $pred(index: Metrics::Index) = { 
		    return (/google\.com$/ !in index$str); 
		 },
		 $break_interval=10secs
		]);
	}

event SSL::log_ssl(rec: SSL::Info)
	{
	if ( rec?$server_name )
		Metrics::add_data(SSL_SERVERNAME, [$str=rec$server_name], 1);
	}
