@load ./main

module Measurement;

event Measurement::finish_period(filter: Filter)
	{
	local data = store[filter$id, filter$name];
	if ( filter?$period_finished )
		filter$period_finished(network_time(), filter$id, filter$name, data);

	reset(filter);
	
	schedule filter$every { Measurement::finish_period(filter) };
	}
	
	
function data_added(filter: Filter, index: Index, val: ResultVal)
	{
	if ( check_thresholds(filter, index, val, 1.0) )
		threshold_crossed(filter, index, val);
	}
