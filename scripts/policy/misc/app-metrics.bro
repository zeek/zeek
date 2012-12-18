@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/metrics

module AppMetrics;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:         time   &log;
		app:        string &log;
		uniq_hosts: count  &log;
		hits:       count  &log;
		bytes:      count  &log;
	};

	## The frequency of logging the stats collected by this script.
	const break_interval = 15mins &redef;
}

function app_metrics_rollup(index: Metrics::Index, vals: table[string, string] of Metrics::ResultVal) 
	{
	local l: Info;
	l$ts = network_time();
	for ( [metric_name, filter_name] in vals )
		{
		local val = vals[metric_name, filter_name];
		l$app = index$str;
		if ( metric_name == "apps.bytes" )
			l$bytes = double_to_count(floor(val$sum));
		else if ( metric_name == "apps.hits" )
			{
			l$hits = val$num;
			l$uniq_hosts = val$unique;
			}
		}
	Log::write(LOG, l);
	}

event bro_init() &priority=3
	{
	Log::create_stream(AppMetrics::LOG, [$columns=Info]);

	Metrics::create_index_rollup("AppMetrics", app_metrics_rollup);
	Metrics::add_filter("apps.bytes", [$every=break_interval, $measure=set(Metrics::SUM),    $period_finished=Metrics::write_log, $rollup="AppMetrics"]);
	Metrics::add_filter("apps.hits",  [$every=break_interval, $measure=set(Metrics::UNIQUE), $rollup="AppMetrics"]);
	}

function do_metric(id: conn_id, hostname: string, size: count)
	{
	if ( /youtube\.com$/ in hostname && size > 512*1024 )
		{
		Metrics::add_data("apps.bytes", [$str="youtube"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="youtube"], [$str=cat(id$orig_h)]);
		}
	else if ( /(\.facebook\.com|\.fbcdn\.net)$/ in hostname && size > 20 )
		{
		Metrics::add_data("apps.bytes", [$str="facebook"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="facebook"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.google\.com$/ in hostname && size > 20 ) 
		{
		Metrics::add_data("apps.bytes", [$str="google"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="google"], [$str=cat(id$orig_h)]);
		}
	else if ( /nflximg\.com$/ in hostname && size > 200*1024 ) 
		{
		Metrics::add_data("apps.bytes", [$str="netflix"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="netflix"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.(pandora|p-cdn)\.com$/ in hostname && size > 512*1024 )
		{
		Metrics::add_data("apps.bytes", [$str="pandora"], [$num=size]);
		Metrics::add_data("apps.hits",  [$str="pandora"], [$str=cat(id$orig_h)]);
		}
	else if ( /gmail\.com$/ in hostname && size > 20 )
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
		do_metric(c$id, c$resp_hostname, c$resp$size);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if( rec?$host )
		do_metric(rec$id, rec$host, rec$response_body_len);
	}
