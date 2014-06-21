@load ../main

module AppStats;

hook add_sumstats(id: conn_id, hostname: string, size: count)
	{
	if ( /\.google\.com$/ in hostname && size > 20 )
		{
		SumStats::observe("apps.bytes", [$str="google"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="google"], [$str=cat(id$orig_h)]);
		}
	}