@load ./main

module SumStats;

event SumStats::process_epoch_result(ss: SumStat, now: time, data: ResultTable)
	{
	# TODO: is this the right processing group size?
	local i = 50;
	local keys_to_delete: vector of SumStats::Key = vector();

	for ( key, res in data )
		{
		ss$epoch_result(now, key, res);
		keys_to_delete += key;

		if ( --i == 0 )
			break;
		}

	for ( idx in keys_to_delete )
		delete data[keys_to_delete[idx]];

	if ( |data| > 0 )
		# TODO: is this the right interval?
		schedule 0.01 secs { SumStats::process_epoch_result(ss, now, data) };
	else if ( ss?$epoch_finished )
		ss$epoch_finished(now);
	}

event SumStats::finish_epoch(ss: SumStat)
	{
	if ( ss$name in result_store )
		{
		if ( ss?$epoch_result )
			{
			local data = result_store[ss$name];
			local now = network_time();
			if ( zeek_is_terminating() )
				{
				for ( key, val in data )
					ss$epoch_result(now, key, val);

				if ( ss?$epoch_finished )
					ss$epoch_finished(now);
				}
			else
				{
				if ( |data| > 0 )
					event SumStats::process_epoch_result(ss, now, copy(data));
				else
					{
					if ( ss?$epoch_finished )
						ss$epoch_finished(now);
					}
				}
			}

		# We can reset here because we know that the reference
		# to the data will be maintained by the process_epoch_result
		# event.
		reset(ss);
		}

	if ( ss$epoch != 0secs )
		schedule ss$epoch { SumStats::finish_epoch(ss) };
	}

function data_added(ss: SumStat, key: Key, result: Result)
	{
	if ( check_thresholds(ss, key, result, 1.0) )
		threshold_crossed(ss, key, result);
	}

function request(ss_name: string): ResultTable &deprecated="Remove in v6.1.  Usage testing indicates this function is unused."
	{
	# This only needs to be implemented this way for cluster compatibility.
	return when [ss_name] ( T )
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
	return when [ss_name, key] ( T )
		{
		if ( ss_name in result_store && key in result_store[ss_name] )
			return result_store[ss_name][key];
		else
			return table();
		}
	}
