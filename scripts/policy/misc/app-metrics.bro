@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/measurement

module AppMeasurement;

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

redef record connection += {
	resp_hostname: string &optional;
};

function app_metrics_rollup(index: Measurement::Index, vals: table[string, string] of Measurement::ResultVal) 
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
	}

event bro_init() &priority=3
	{
	Log::create_stream(AppMeasurement::LOG, [$columns=Info]);

	#Measurement::create_index_rollup("AppMeasurement", app_metrics_rollup);
	#Measurement::add_filter("apps.bytes", [$every=break_interval, $measure=set(Measurement::SUM),    $rollup="AppMeasurement"]);
	#Measurement::add_filter("apps.hits",  [$every=break_interval, $measure=set(Measurement::UNIQUE), $rollup="AppMeasurement"]);

	Measurement::create([$epoch=break_interval, 
	                     $measurements=table(["apps.bytes"] = [$apply=set(Measurement::SUM)],
	                                         ["apps.hits"]  = [$apply=set(Measurement::UNIQUE)]),
	                     $period_finished(result: Measurement::Results) = 
	                     	{
	                     	local l: Info;
	                     	l$ts = network_time();
	                     	for ( index in result )
	                     		{
	                     		l$bytes      = double_to_count(floor(result[index]["apps.bytes"]$sum));
	                     		l$hits       = result[index]["apps.hits"]$num;
	                     		l$uniq_hosts = result[index]["apps.hits"]$unique;
	                     		Log::write(LOG, l);
	                     		}
	                     	}]);
	}

function do_metric(id: conn_id, hostname: string, size: count)
	{
	if ( /\.youtube\.com$/ in hostname && size > 512*1024 )
		{
		Measurement::add_data("apps.bytes", [$str="youtube"], [$num=size]);
		Measurement::add_data("apps.hits",  [$str="youtube"], [$str=cat(id$orig_h)]);
		}
	else if ( /(\.facebook\.com|\.fbcdn\.net)$/ in hostname && size > 20 )
		{
		Measurement::add_data("apps.bytes", [$str="facebook"], [$num=size]);
		Measurement::add_data("apps.hits",  [$str="facebook"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.google\.com$/ in hostname && size > 20 ) 
		{
		Measurement::add_data("apps.bytes", [$str="google"], [$num=size]);
		Measurement::add_data("apps.hits",  [$str="google"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.nflximg\.com$/ in hostname && size > 200*1024 ) 
		{
		Measurement::add_data("apps.bytes", [$str="netflix"], [$num=size]);
		Measurement::add_data("apps.hits",  [$str="netflix"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.(pandora|p-cdn)\.com$/ in hostname && size > 512*1024 )
		{
		Measurement::add_data("apps.bytes", [$str="pandora"], [$num=size]);
		Measurement::add_data("apps.hits",  [$str="pandora"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.gmail\.com$/ in hostname && size > 20 )
		{
		Measurement::add_data("apps.bytes", [$str="gmail"], [$num=size]);
		Measurement::add_data("apps.hits",  [$str="gmail"], [$str=cat(id$orig_h)]);
		}
}


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
