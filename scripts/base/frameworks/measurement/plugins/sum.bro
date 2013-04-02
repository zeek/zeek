@load base/frameworks/measurement

module Measurement;

export {
	redef enum Calculation += { 
		## Sums the values given.  For string values,
		## this will be the number of strings given.
		SUM
	};

	redef record ResultVal += {
		## For numeric data, this tracks the sum of all values.
		sum: double &default=0.0;
	};

	type threshold_function: function(key: Measurement::Key, result: Measurement::Result): count;
	global sum_threshold: function(data_id: string): threshold_function;
}

function sum_threshold(data_id: string): threshold_function
	{
	return function(key: Measurement::Key, result: Measurement::Result): count
		{
		print fmt("data_id: %s", data_id);
		print result;
		return double_to_count(result[data_id]$sum);
		};
	}

hook init_resultval_hook(r: Reducer, rv: ResultVal)
	{
	if ( SUM in r$apply && ! rv?$sum )
		rv$sum = 0;
	}

hook add_to_reducer_hook(r: Reducer, val: double, data: DataPoint, rv: ResultVal)
	{
	if ( SUM in r$apply )
		rv$sum += val;
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$sum || rv2?$sum )
		{
		result$sum = rv1?$sum ? rv1$sum : 0;
		if ( rv2?$sum )
			result$sum += rv2$sum;
		}
	}