@load base/frameworks/metrics

event bro_init() &priority=3
	{
	Metrics::add_filter("conns.country", [$break_interval=1hr]);
	Metrics::add_filter("hosts.active", [$break_interval=1hr]);
	}

event connection_established(c: connection) &priority=3
	{
	if ( Site::is_local_addr(c$id$orig_h) )
		{
		local loc = lookup_location(c$id$resp_h);
		if ( loc?$country_code )
			Metrics::add_data("conns.country", [$str=loc$country_code], 1);
		}
		
	local the_host = Site::is_local_addr(c$id$orig_h) ? c$id$orig_h : c$id$resp_h;
	# There is no index for this.
	Metrics::add_unique("hosts.active", [], cat(the_host));
	}
