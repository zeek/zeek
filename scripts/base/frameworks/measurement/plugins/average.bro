
module Metrics;

export {
	redef enum Calculation += { 
		## Calculate the average of the values.
		AVERAGE
	};

	redef record ResultVal += {
		## For numeric data, this calculates the average of all values.
		average: double &log &optional;
	};
}

hook add_to_calculation(filter: Filter, val: double, data: DataPoint, result: ResultVal)
	{
	if ( AVERAGE in filter$measure )
		{
		if ( ! result?$average ) 
			result$average = val;
		else
			result$average += (val - result$average) / result$num;
		}
	}

hook plugin_merge_measurements(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$average && rv2?$average )
		result$average = ((rv1$average*rv1$num) + (rv2$average*rv2$num))/(rv1$num+rv2$num);
	else if ( rv1?$average )
		result$average = rv1$average;
	else if ( rv2?$average )
		result$average = rv2$average;
	}