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
