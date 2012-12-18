##! Provides an example of aggregating and limiting collection down to 
##! only local networks.  Additionally, the status code for the response from
##! the request is added into the metric.

@load base/frameworks/metrics
@load base/protocols/http
@load base/utils/site

event bro_init()
	{
	Metrics::add_filter("http.request.by_host_header", 
	                    [$every=1min, $measure=set(Metrics::SUM), 
	                     $pred(index: Metrics::Index, data: Metrics::DataPoint) = { return T; return Site::is_local_addr(index$host); },
	                     $aggregation_mask=24,
	                     $period_finished=Metrics::write_log]);
	
	# Site::local_nets must be defined in order for this to actually do anything.
	Metrics::add_filter("http.request.by_status_code", [$every=1min, $measure=set(Metrics::SUM),
	                                                    $aggregation_table=Site::local_nets_table,
	                                                    $period_finished=Metrics::write_log]);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if ( rec?$host )
		Metrics::add_data("http.request.by_host_header", [$str=rec$host], [$num=1]);
	if ( rec?$status_code )
		Metrics::add_data("http.request.by_status_code", [$host=rec$id$orig_h, $str=fmt("%d", rec$status_code)], [$num=1]);
	}
