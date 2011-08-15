@load base/frameworks/metrics/main
@load base/protocols/http/main
@load base/utils/site

redef enum Metrics::ID += {
	HTTP_REQUESTS_BY_STATUS_CODE,
	HTTP_REQUESTS_BY_HOST_HEADER,
};

event bro_init()
	{
	# TODO: these are waiting on a fix with table vals + records before they will work.
	#Metrics::add_filter(HTTP_REQUESTS_BY_HOST_HEADER, 
	#                    [$pred(index: Index) = { return Site:is_local_addr(index$host) },
	#                     $aggregation_mask=24,
	#                     $break_interval=5mins]);
	#
	## Site::local_nets must be defined in order for this to actually do anything.
	#Metrics::add_filter(HTTP_REQUESTS_BY_STATUS_CODE, [$aggregation_table=Site::local_nets_table,
	#                                                   $break_interval=5mins]);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if ( rec?$host )
		Metrics::add_data(HTTP_REQUESTS_BY_HOST_HEADER, [$str=rec$host], 1);
	if ( rec?$status_code )
		Metrics::add_data(HTTP_REQUESTS_BY_STATUS_CODE, [$host=rec$id$orig_h, $str=fmt("%d", rec$status_code)], 1);
	}
