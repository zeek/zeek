@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/sumstats

module AppStats;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp when the log line was finished and written.
		ts:         time   &log;
		## Time interval that the log line covers.
		ts_delta:   interval &log;
		## The name of the "app", like "facebook" or "netflix".
		app:        string &log;
		## The number of unique local hosts using the app.
		uniq_hosts: count  &log;
		## The number of hits to the app in total.
		hits:       count  &log;
		## The total number of bytes received by users of the app.
		bytes:      count  &log;
	};

	## The frequency of logging the stats collected by this script.
	const break_interval = 15mins &redef;
}

redef record connection += {
	resp_hostname: string &optional;
};

event bro_init() &priority=3
	{
	Log::create_stream(AppSumStats::LOG, [$columns=Info]);

	local r1: SumStats::Reducer = [$stream="apps.bytes", $apply=set(SumStats::SUM)];
	local r2: SumStats::Reducer = [$stream="apps.hits",  $apply=set(SumStats::UNIQUE)];
	SumStats::create([$epoch=break_interval, 
	                  $reducers=set(r1, r2),
	                  $epoch_finished(data: SumStats::ResultTable) = 
	                  	{
	                  	local l: Info;
	                  	l$ts = network_time();
	                  	l$ts_delta = break_interval;
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

function add_sumstats(id: conn_id, hostname: string, size: count)
	{
	if ( /\.youtube\.com$/ in hostname && size > 512*1024 )
		{
		SumStats::observe("apps.bytes", [$str="youtube"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="youtube"], [$str=cat(id$orig_h)]);
		}
	else if ( /(\.facebook\.com|\.fbcdn\.net)$/ in hostname && size > 20 )
		{
		SumStats::observe("apps.bytes", [$str="facebook"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="facebook"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.google\.com$/ in hostname && size > 20 ) 
		{
		SumStats::observe("apps.bytes", [$str="google"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="google"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.nflximg\.com$/ in hostname && size > 200*1024 ) 
		{
		SumStats::observe("apps.bytes", [$str="netflix"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="netflix"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.(pandora|p-cdn)\.com$/ in hostname && size > 512*1024 )
		{
		SumStats::observe("apps.bytes", [$str="pandora"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="pandora"], [$str=cat(id$orig_h)]);
		}
	else if ( /\.gmail\.com$/ in hostname && size > 20 )
		{
		SumStats::observe("apps.bytes", [$str="gmail"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="gmail"], [$str=cat(id$orig_h)]);
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
		add_sumstats(c$id, c$resp_hostname, c$resp$size);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if( rec?$host )
		add_sumstats(rec$id, rec$host, rec$response_body_len);
	}
