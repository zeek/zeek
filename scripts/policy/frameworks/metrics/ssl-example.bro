@load base/frameworks/metrics/main
@load base/protocols/ssl/main

redef enum Metrics::ID += {
	SSL_SERVERNAME,
};

event bro_init()
	{
	Metrics::add_filter(SSL_SERVERNAME, 
		[$name="no-google-ssl-servers",
		 $pred(entry: Metrics::Entry) = { 
		    return (/google\.com$/ !in entry$index); 
		 },
		 $break_interval=10secs
		]);
	}

event SSL::log_ssl(rec: SSL::Info)
	{
	if ( rec?$server_name )
		Metrics::add_data(SSL_SERVERNAME, [$index=rec$server_name]);
	}
