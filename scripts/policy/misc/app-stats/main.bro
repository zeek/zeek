##! AppStats collects information about web applications in use
##! on the network.  

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

global add_sumstats: hook(id: conn_id, hostname: string, size: count);


event bro_init() &priority=3
	{
	Log::create_stream(AppStats::LOG, [$columns=Info]);

	local r1: SumStats::Reducer = [$stream="apps.bytes", $apply=set(SumStats::SUM)];
	local r2: SumStats::Reducer = [$stream="apps.hits",  $apply=set(SumStats::UNIQUE)];
	SumStats::create([$name="app-metrics",
	                  $epoch=break_interval,
	                  $reducers=set(r1, r2),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local l: Info;
	                  	l$ts         = network_time();
	                  	l$ts_delta   = break_interval;
	                  	l$app        = key$str;
	                  	l$bytes      = double_to_count(floor(result["apps.bytes"]$sum));
	                  	l$hits       = result["apps.hits"]$num;
	                  	l$uniq_hosts = result["apps.hits"]$unique;
	                  	Log::write(LOG, l);
	                  	}]);
	}

event ssl_established(c: connection)
	{
	if ( c?$ssl && c$ssl?$server_name )
		c$resp_hostname = c$ssl$server_name;
	}

event connection_finished(c: connection)
	{
	if ( c?$resp_hostname )
		hook add_sumstats(c$id, c$resp_hostname, c$resp$size);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if( rec?$host )
		hook add_sumstats(rec$id, rec$host, rec$response_body_len);
	}
