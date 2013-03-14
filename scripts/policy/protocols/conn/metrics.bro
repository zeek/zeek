@load base/frameworks/measurement
@load base/utils/site

event bro_init() &priority=3
	{
	Metrics::add_filter("conns.country", [$every=1hr, $measure=set(Metrics::SUM),
	                                      $period_finished=Metrics::write_log]);
	Metrics::add_filter("hosts.active", [$every=1hr, $measure=set(Metrics::SUM),
	                                     $period_finished=Metrics::write_log]);
	}

event connection_established(c: connection) &priority=3
	{
	if ( Site::is_local_addr(c$id$orig_h) )
		{
		local loc = lookup_location(c$id$resp_h);
		if ( loc?$country_code )
			Metrics::add_data("conns.country", [$str=loc$country_code], [$num=1]);
		}
		
	local the_host = Site::is_local_addr(c$id$orig_h) ? c$id$orig_h : c$id$resp_h;
	# There is no index for this.
	Metrics::add_data("hosts.active", [], [$str=cat(the_host)]);
	}
