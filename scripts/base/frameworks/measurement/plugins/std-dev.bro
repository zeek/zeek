@load ./sum
@load ./variance

module Metrics;

export {
	redef enum Calculation += { 
		## Find the standard deviation of the values.
		STD_DEV
	};

	redef record ResultVal += {
		## For numeric data, this calculates the standard deviation.
		std_dev:  double &log &optional;
	};
}

# This depends on the variance plugin which uses priority -5
hook add_to_calculation(filter: Filter, val: double, data: DataPoint, result: ResultVal) &priority=-10
	{
	if ( STD_DEV in filter$measure )
		{
		if ( result?$variance )
			result$std_dev = sqrt(result$variance);
		}
	}

hook plugin_merge_measurements(result: ResultVal, rv1: ResultVal, rv2: ResultVal) &priority=-10
	{
	if ( rv1?$sum || rv2?$sum )
		{
		result$sum = rv1?$sum ? rv1$sum : 0;
		if ( rv2?$sum )
			result$sum += rv2$sum;
		}
	}