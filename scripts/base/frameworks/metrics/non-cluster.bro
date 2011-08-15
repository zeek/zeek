
module Metrics;

export {

}

event Metrics::log_it(filter: Filter)
	{
	local id = filter$id;
	local name = filter$name;
	
	write_log(network_time(), filter, store[id, name]);
	reset(filter);
	
	schedule filter$break_interval { Metrics::log_it(filter) };
	}
