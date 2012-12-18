@load ./main

module Metrics;

event Metrics::finish_period(filter: Filter)
	{
	local data = store[filter$id, filter$name];
	if ( filter?$rollup )
		{
		for ( index in data )
			{
			if ( index !in rollup_store )
				rollup_store[index] = table();
			rollup_store[index][filter$id, filter$name] = data[index];

			# If all of the result vals are stored then the rollup callback can be executed.
			if ( |rollup_store[index]| == |rollups[filter$rollup]$filters| )
				{
				rollups[filter$rollup]$callback(index, rollup_store[index]);
				}
			}
		}

	if ( filter?$period_finished )
		filter$period_finished(network_time(), filter$id, filter$name, data);

	reset(filter);
	
	schedule filter$every { Metrics::finish_period(filter) };
	}
	
	
function data_added(filter: Filter, index: Index, val: ResultVal)
	{
	if ( check_thresholds(filter, index, val, 1.0) )
		threshold_crossed(filter, index, val);
	}
