
module Metrics;

export {
	redef enum Calculation += { 
		## Find the maximum value.
		MAX
	};

	redef record ResultVal += {
		## For numeric data, this tracks the maximum value given.
		max:      double        &log &optional;
	};
}

hook add_to_calculation(filter: Filter, val: double, data: DataPoint, result: ResultVal)
	{
	if ( MAX in filter$measure )
		{
		if ( ! result?$max ) 
			result$max = val;
		else if ( val > result$max )
			result$max = val;
		}
	}

hook plugin_merge_measurements(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$max && rv2?$max )
		result$max = (rv1$max > rv2$max) ? rv1$max : rv2$max;
	else if ( rv1?$max )
		result$max = rv1$max;
	else if ( rv2?$max )
		result$max = rv2$max;
	}


