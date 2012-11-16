
event bro_init() &priority=5
	{
	Metrics::add_filter("conn.orig.data", 
	                    [$every=5mins,
	                     $measure=set(Metrics::VARIANCE, Metrics::AVG, Metrics::MAX, Metrics::MIN, Metrics::STD_DEV)]);
	Metrics::add_filter("conn.resp.data", 
	                    [$every=5mins,
	                     $measure=set(Metrics::VARIANCE, Metrics::AVG, Metrics::MAX, Metrics::MIN, Metrics::STD_DEV)]);
	}


event connection_state_remove(c: connection)
	{
	if ( ! (c$conn$conn_state == "SF" && c$conn$proto == tcp) )
		return;

	if ( Site::is_local_addr(c$id$orig_h) )
		Metrics::add_data("conn.orig.data", [$host=c$id$orig_h], [$num=c$orig$size]);
	if ( Site::is_local_addr(c$id$resp_h) )
		Metrics::add_data("conn.resp.data", [$host=c$id$resp_h], [$num=c$resp$size]);
	}