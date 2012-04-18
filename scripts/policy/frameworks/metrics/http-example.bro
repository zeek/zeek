##! Provides an example of aggregating and limiting collection down to 
##! only local networks.  Additionally, the status code for the response from
##! the request is added into the metric.

@load base/frameworks/metrics
@load base/protocols/http
@load base/utils/site

redef enum Metrics::ID += {
	## Measures HTTP requests indexed on both the request host and the response
	## code from the server.
	HTTP_REQUESTS_BY_STATUS_CODE,

	## Currently unfinished and not working.
	HTTP_REQUESTS_BY_HOST_HEADER,
};

event bro_init()
	{
	# TODO: these are waiting on a fix with table vals + records before they will work.
	#Metrics::add_filter(HTTP_REQUESTS_BY_HOST_HEADER, 
	#                    [$pred(index: Metrics::Index) = { return Site::is_local_addr(index$host); },
	#                     $aggregation_mask=24,
	#                     $break_interval=1min]);
	
	# Site::local_nets must be defined in order for this to actually do anything.
	Metrics::add_filter(HTTP_REQUESTS_BY_STATUS_CODE, [$aggregation_table=Site::local_nets_table,
	                                                   $break_interval=1min]);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if ( rec?$host )
		Metrics::add_data(HTTP_REQUESTS_BY_HOST_HEADER, [$str=rec$host], 1);
	if ( rec?$status_code )
		Metrics::add_data(HTTP_REQUESTS_BY_STATUS_CODE, [$host=rec$id$orig_h, $str=fmt("%d", rec$status_code)], 1);
	}
