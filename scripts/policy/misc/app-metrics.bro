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
	const break_interval = 1min &redef;
}

redef record connection += {
	resp_hostname: string &optional;
};


event bro_init() &priority=3
	{
	Log::create_stream(AppMeasurement::LOG, [$columns=Info]);

	local r1: Measurement::Reducer = [$stream="apps.bytes", $apply=set(Measurement::SUM)];
	local r2: Measurement::Reducer = [$stream="apps.hits",  $apply=set(Measurement::UNIQUE)];
	Measurement::create([$epoch=break_interval, 
	                     $reducers=set(r1, r2),
	                     $period_finished(data: Measurement::ResultTable) = 
	                     	{
	                     	local l: Info;
	                     	l$ts = network_time();
	                     	for ( key in data )
	                     		{
	                     		local result = data[key];
	                     		l$app        = key$str;
	                     		l$bytes      = double_to_count(floor(result["apps.bytes"]$sum));
	                     		l$hits       = result["apps.hits"]$num;
	                     		l$uniq_hosts = result["apps.hits"]$unique;
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
