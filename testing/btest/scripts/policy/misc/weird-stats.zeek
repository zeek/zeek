# @TEST-EXEC: btest-bg-run zeek zeek %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff zeek/weird_stats.log

@load misc/weird-stats

redef exit_only_after_terminate = T;
redef WeirdStats::weird_stat_interval = 5sec;

event die()
	{
	terminate();
	}

event gen_weirds(n: count, done: bool &default = F)
	{
	while ( n != 0 )
		{
		Reporter::net_weird("my_weird");
		--n;
		}

	if ( done )
		schedule 5sec { die() };
	}

event zeek_init()
	{
	event gen_weirds(1000);
	schedule 7.5sec { gen_weirds(2000) } ;
	schedule 12.5sec { gen_weirds(10, T) } ;
	}
