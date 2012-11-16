@load ./main

module Metrics;

event Metrics::log_it(filter: Filter)
	{
	local id = filter$id;
	local name = filter$name;

	write_log(network_time(), filter, store[id, name]);
	reset(filter);
	
	schedule filter$every { Metrics::log_it(filter) };
	}
	
	
function data_added(filter: Filter, index: Index, val: ResultVal)
	{
	if ( check_thresholds(filter, index, val, 1.0) )
		threshold_crossed(filter, index, val);
	}
