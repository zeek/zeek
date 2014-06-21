@load ../main

module AppStats;

hook add_sumstats(id: conn_id, hostname: string, size: count)
	{
	if ( /\.(pandora|p-cdn)\.com$/ in hostname && size > 512*1024 )
		{
		SumStats::observe("apps.bytes", [$str="pandora"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="pandora"], [$str=cat(id$orig_h)]);
		}
	}