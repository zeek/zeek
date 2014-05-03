@load base/utils/site
@load base/frameworks/sumstats

redef Site::local_nets += { 10.0.0.0/8 };

module MimeMetrics;

export {

	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp when the log line was finished and written.
		ts:         time   &log;
		## Time interval that the log line covers.
		ts_delta:   interval &log;
		## The mime type
		mtype:        string &log;
		## The number of unique local hosts that fetched this mime type
		uniq_hosts: count  &log;
		## The number of hits to the mime type
		hits:       count  &log;
		## The total number of bytes received by this mime type
		bytes:      count  &log;
	};

	## The frequency of logging the stats collected by this script.
	const break_interval = 5mins &redef;
}

event bro_init() &priority=3
	{
	Log::create_stream(MimeMetrics::LOG, [$columns=Info]);
	local r1: SumStats::Reducer = [$stream="mime.bytes",
	                               $apply=set(SumStats::SUM)];
	local r2: SumStats::Reducer = [$stream="mime.hits", 
	                               $apply=set(SumStats::UNIQUE)];
	SumStats::create([$name="mime-metrics",
	                  $epoch=break_interval,
	                  $reducers=set(r1, r2),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                        {
	                        local l: Info;
	                        l$ts         = network_time();
	                        l$ts_delta   = break_interval;
	                        l$mtype      = key$str;
	                        l$bytes      = double_to_count(floor(result["mime.bytes"]$sum));
	                        l$hits       = result["mime.hits"]$num;
	                        l$uniq_hosts = result["mime.hits"]$unique;
	                        Log::write(MimeMetrics::LOG, l);
	                        }]);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if ( Site::is_local_addr(rec$id$orig_h) && rec?$resp_mime_types )
		{
		local mime_type = rec$resp_mime_types[0];
		SumStats::observe("mime.bytes", [$str=mime_type],
		                  [$num=rec$response_body_len]);
		SumStats::observe("mime.hits",  [$str=mime_type],
		                  [$str=cat(rec$id$orig_h)]);
		}
	}
