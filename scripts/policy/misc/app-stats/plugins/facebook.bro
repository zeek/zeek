@load ../main

module AppStats;

hook add_sumstats(id: conn_id, hostname: string, size: count)
	{
	if ( /\.(facebook\.com|fbcdn\.net)$/ in hostname && size > 20 )
		{
		SumStats::observe("apps.bytes", [$str="facebook"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="facebook"], [$str=cat(id$orig_h)]);
		}
	}