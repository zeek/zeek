# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff .stdout

redef exit_only_after_terminate=T;


## Requesting a full sumstats resulttable is not supported yet.
#event on_demand()
#	{
#	when ( local results = SumStats::request("test") )
#		{
#		print "Complete SumStat request";
#		for ( key in results )
#			{
#			print fmt("    Host: %s -> %.0f", key$host, results[key]["test.reducer"]$sum);
#			}
#		}
#	}

event on_demand_key()
	{
	local host = 1.2.3.4;
	when ( local result = SumStats::request_key("test", [$host=host]) )
		{
		print fmt("Key request for %s", host);
		print fmt("    Host: %s -> %.0f", host, result["test.reducer"]$sum);
		terminate();
		}
	}

event zeek_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="test.reducer", 
	                               $apply=set(SumStats::SUM)];
	SumStats::create([$name="test",
	                  $epoch=1hr,
	                  $reducers=set(r1)]);

	# Seed some data but notice there are no callbacks defined in the sumstat!
	SumStats::observe("test.reducer", [$host=1.2.3.4], [$num=42]);
	SumStats::observe("test.reducer", [$host=4.3.2.1], [$num=7]);

	#schedule 0.1 secs { on_demand() };
	schedule 1 secs { on_demand_key() };
	}

