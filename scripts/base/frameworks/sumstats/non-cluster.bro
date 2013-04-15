@load ./main

module SumStats;

event SumStats::finish_epoch(m: SumStats)
	{
	if ( m$id in result_store )
		{
		local data = result_store[m$id];
		if ( m?$epoch_finished )
			m$epoch_finished(data);

		reset(m);
		}

	schedule m$epoch { SumStats::finish_epoch(m) };
	}
	
	
function data_added(m: SumStats, key: Key, result: Result)
	{
	if ( check_thresholds(m, key, result, 1.0) )
		threshold_crossed(m, key, result);
	}
