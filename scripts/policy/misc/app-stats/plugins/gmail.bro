@load ../main

module AppStats;

hook add_sumstats(id: conn_id, hostname: string, size: count)
	{
	if ( /\.gmail\.com$/ in hostname && size > 20 )
		{
		SumStats::observe("apps.bytes", [$str="gmail"], [$num=size]);
		SumStats::observe("apps.hits",  [$str="gmail"], [$str=cat(id$orig_h)]);
		}
	}