@load ../main

module AppStats;

hook add_sumstats(id: conn_id, hostname: string, size: count)
	{
	if ( /\.youtube\.com$/ in hostname && size > 512*1024 )
		{
		SumStats::observe("apps.bytes", [$str="youtube"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="youtube"], [$str=cat(id$orig_h)]);
		}
	}