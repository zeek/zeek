@load ./main

module SumStats;

event SumStats::finish_epoch(ss: SumStat)
	{
	if ( ss$id in result_store )
		{
		local data = result_store[ss$id];
		if ( ss?$epoch_finished )
			ss$epoch_finished(data);

		reset(ss);
		}

	schedule ss$epoch { SumStats::finish_epoch(ss) };
	}


function data_added(ss: SumStat, key: Key, result: Result)
	{
	if ( check_thresholds(ss, key, result, 1.0) )
		threshold_crossed(ss, key, result);
	}
