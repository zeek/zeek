@load base/protocols/http
@load base/protocols/ssl

@load base/frameworks/metrics

module AppMetrics;

export {
	## The metric break interval for the default stats collected by this script.
	const break_interval = 1hr &redef;
}

event bro_init() &priority=3
	{
	Metrics::add_filter("apps.bytes", [$break_interval=break_interval]);
	Metrics::add_filter("apps.views", [$break_interval=break_interval]);
	Metrics::add_filter("apps.users", [$break_interval=break_interval]);
	}

function do_metric(id: conn_id, hostname: string, size: count)
	{
	if ( /youtube/ in hostname && size > 512*1024 ) 
		{
		Metrics::add_data("apps.bytes", [$str="youtube"], size);
		Metrics::add_data("apps.views", [$str="youtube"], 1);
		Metrics::add_unique("apps.users", [$str="youtube"], cat(id$orig_h));
		}
	else if ( /facebook.com|fbcdn.net/ in hostname && size > 20 )
		{
		Metrics::add_data("apps.bytes", [$str="facebook"], size);
		Metrics::add_data("apps.views", [$str="facebook"], 1);
		Metrics::add_unique("apps.users", [$str="facebook"], cat(id$orig_h));
		}
	else if ( /google.com/ in hostname && size > 20 ) 
		{
		Metrics::add_data("apps.bytes", [$str="google"], size);
		Metrics::add_data("apps.views", [$str="google"], 1);
		Metrics::add_unique("apps.users", [$str="google"], cat(id$orig_h));
		}
	else if ( /nflximg.com/ in hostname && size > 200*1024 ) 
		{
		Metrics::add_data("apps.bytes", [$str="netflix"], size);
		Metrics::add_data("apps.views", [$str="netflix"], 1);
		Metrics::add_unique("apps.users", [$str="netflix"], cat(id$orig_h));
		}
	else if ( /pandora.com/ in hostname && size > 512*1024 )
		{
		Metrics::add_data("apps.bytes", [$str="pandora"], size);
		Metrics::add_data("apps.views", [$str="pandora"], 1);
		Metrics::add_unique("apps.users", [$str="pandora"], cat(id$orig_h));
		}
	else if ( /gmail.com/ in hostname && size > 20 )
		{
		Metrics::add_data("apps.bytes", [$str="gmail"], size);
		Metrics::add_data("apps.views", [$str="gmail"], 1);
		Metrics::add_unique("apps.users", [$str="gmail"], cat(id$orig_h));
		}
}

redef record connection += {
	resp_hostname: string &optional;
};

event ssl_established(c: connection)
	{
	if ( c?$ssl && c$ssl?$server_name )
		c$resp_hostname = c$ssl$server_name;
	}

event connection_finished(c: connection)
	{
	if ( c?$resp_hostname )
		do_metric(c$id, c$resp_hostname, c$resp$num_bytes_ip);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if( rec?$host )
		do_metric(rec$id, rec$host, rec$response_body_len);
	}
