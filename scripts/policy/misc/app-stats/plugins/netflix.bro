@load ../main

module AppStats;

hook add_sumstats(id: conn_id, hostname: string, size: count)
	{
	if ( /\.nflximg\.com$/ in hostname && size > 200*1024 )
		{
		SumStats::observe("apps.bytes", [$str="netflix"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="netflix"], [$str=cat(id$orig_h)]);
		}
	}