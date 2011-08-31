@load ./main

module Metrics;

event Metrics::log_it(filter: Filter)
	{
	local id = filter$id;
	local name = filter$name;
	
	write_log(network_time(), filter, store[id, name]);
	reset(filter);
	
	schedule filter$break_interval { Metrics::log_it(filter) };
	}
	
	
function data_added(filter: Filter, index: Index, val: count)
	{
	if ( check_notice(filter, index, val) )
		do_notice(filter, index, val);
	}
