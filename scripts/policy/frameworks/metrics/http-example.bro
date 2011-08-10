@load base/frameworks/metrics/main
@load base/protocols/http/main
@load base/utils/site

redef enum Metrics::ID += {
	HTTP_REQUESTS_BY_STATUS_CODE,
	HTTP_REQUESTS_BY_HOST_HEADER,
};

event bro_init()
	{
	Metrics::add_filter(HTTP_REQUESTS_BY_HOST_HEADER, [$break_interval=5mins]);
	
	# Site::local_nets must be defined in order for this to actually do anything.
	Metrics::add_filter(HTTP_REQUESTS_BY_STATUS_CODE, [$aggregation_table=Site::local_nets_table, $break_interval=5mins]);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if ( rec?$host )
		Metrics::add_data(HTTP_REQUESTS_BY_HOST_HEADER, [$index=rec$host]);
	if ( rec?$status_code )
		Metrics::add_data(HTTP_REQUESTS_BY_STATUS_CODE, [$host=rec$id$orig_h, $index=fmt("%d", rec$status_code)]);
	}
