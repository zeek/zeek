
module Measurement;

export {
	redef enum Calculation += { 
		## Sums the values given.  For string values,
		## this will be the number of strings given.
		SUM
	};

	redef record Result += {
		## For numeric data, this tracks the sum of all values.
		sum:      double        &log &optional;
	};
}

hook add_to_reducer(r: Reducer, val: double, data: DataPoint, result: Result)
	{
	if ( SUM in r$apply )
		{
		if ( ! result?$sum ) 
			result$sum = 0;
		result$sum += val;
		}
	}

hook compose_resultvals_hook(result: Result, rv1: Result, rv2: Result)
	{
	if ( rv1?$sum || rv2?$sum )
		{
		result$sum = rv1?$sum ? rv1$sum : 0;
		if ( rv2?$sum )
			result$sum += rv2$sum;
		}
	}