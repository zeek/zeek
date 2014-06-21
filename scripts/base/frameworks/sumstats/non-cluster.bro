@load ./main

module SumStats;

event SumStats::process_epoch_result(ss: SumStat, now: time, data: ResultTable)
	{
	# TODO: is this the right processing group size?
	local i = 50;
	for ( key in data )
		{
		ss$epoch_result(now, key, data[key]);
		delete data[key];

		if ( |data| == 0 )
			{
			if ( ss?$epoch_finished )
				ss$epoch_finished(now);

			# Now that no data is left we can finish.
			return;
			}

		i = i-1;
		if ( i == 0 )
			{
			# TODO: is this the right interval?
			schedule 0.01 secs { process_epoch_result(ss, now, data) };
			break;
			}
		}
	}

event SumStats::finish_epoch(ss: SumStat)
	{
	if ( ss$name in result_store )
		{
		if ( ss?$epoch_result )
			{
			local data = result_store[ss$name];
			local now = network_time();
			if ( bro_is_terminating() )
				{
				for ( key in data )
					ss$epoch_result(now, key, data[key]);

				if ( ss?$epoch_finished )
					ss$epoch_finished(now);
				}
			else
				{
				event SumStats::process_epoch_result(ss, now, data);
				}
			}
		
		# We can reset here because we know that the reference
		# to the data will be maintained by the process_epoch_result
		# event.
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