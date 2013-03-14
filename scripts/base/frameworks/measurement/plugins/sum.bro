
module Metrics;

export {
	redef enum Calculation += { 
		## Sums the values given.  For string values,
		## this will be the number of strings given.
		SUM
	};

	redef record ResultVal += {
		## For numeric data, this tracks the sum of all values.
		sum:      double        &log &optional;
	};
}

hook add_to_calculation(filter: Filter, val: double, data: DataPoint, result: ResultVal)
	{
	if ( SUM in filter$measure )
		{
		if ( ! result?$sum ) 
			result$sum = 0;
		result$sum += val;
		}
	}

hook plugin_merge_measurements(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$sum || rv2?$sum )
		{
		result$sum = rv1?$sum ? rv1$sum : 0;
		if ( rv2?$sum )
			result$sum += rv2$sum;
		}
	}