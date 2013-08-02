@load ./main

module SumStats;

event SumStats::finish_epoch(ss: SumStat)
	{
	if ( ss$name in result_store )
		{
		local now = network_time();

		if ( ss?$epoch_result )
			{
			local data = result_store[ss$name];
			# TODO: don't block here.
			for ( key in data )
				ss$epoch_result(now, key, data[key]);
			}

		if ( ss?$epoch_finished )
			ss$epoch_finished(now);

		reset(ss);
		}

	schedule ss$epoch { SumStats::finish_epoch(ss) };
	}

function data_added(ss: SumStat, key: Key, result: Result)
	{
	if ( check_thresholds(ss, key, result, 1.0) )
		threshold_crossed(ss, key, result);
	}

function request(ss_name: string): ResultTable
	{
	# This only needs to be implemented this way for cluster compatibility.
	return when ( T )
		{
		if ( ss_name in result_store )
			return result_store[ss_name];
		else
			return table();
		}
	}

function request_key(ss_name: string, key: Key): Result
	{
	# This only needs to be implemented this way for cluster compatibility.
	return when ( T )
		{
		if ( ss_name in result_store && key in result_store[ss_name] )
			return result_store[ss_name][key];
		else
			return table();
		}
	}