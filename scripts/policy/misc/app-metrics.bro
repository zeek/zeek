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
	Metrics::add_filter("apps.bytes", [$every=break_interval, $measure=set(Metrics::SUM)]);
	Metrics::add_filter("apps.hits",  [$every=break_interval, $measure=set(Metrics::SUM, Metrics::UNIQUE)]);
	}

function do_metric(id: conn_id, hostname: string, size: count)
	{
	if ( /youtube/ in hostname && size > 512*1024 ) 
		{
		Metrics::add_data("apps.bytes", [$str="youtube"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="youtube"], [$str=cat(id$orig_h)]);
		}
	else if ( /facebook.com|fbcdn.net/ in hostname && size > 20 )
		{
		Metrics::add_data("apps.bytes", [$str="facebook"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="facebook"], [$str=cat(id$orig_h)]);
		}
	else if ( /google.com/ in hostname && size > 20 ) 
		{
		Metrics::add_data("apps.bytes", [$str="google"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="google"], [$str=cat(id$orig_h)]);
		}
	else if ( /nflximg.com/ in hostname && size > 200*1024 ) 
		{
		Metrics::add_data("apps.bytes", [$str="netflix"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="netflix"], [$str=cat(id$orig_h)]);
		}
	else if ( /pandora.com/ in hostname && size > 512*1024 )
		{
		Metrics::add_data("apps.bytes", [$str="pandora"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="pandora"], [$str=cat(id$orig_h)]);
		}
	else if ( /gmail.com/ in hostname && size > 20 )
		{
		Metrics::add_data("apps.bytes", [$str="gmail"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="gmail"], [$str=cat(id$orig_h)]);
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
