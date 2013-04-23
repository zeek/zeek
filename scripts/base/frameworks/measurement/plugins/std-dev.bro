@load ./sum
@load ./variance

module Measurement;

export {
	redef enum Calculation += { 
		## Find the standard deviation of the values.
		STD_DEV
	};

	redef record Result += {
		## For numeric data, this calculates the standard deviation.
		std_dev:  double &log &optional;
	};
}

# This depends on the variance plugin which uses priority -5
hook add_to_reducer(r: Reducer, val: double, data: DataPoint, result: Result)
	{
	if ( STD_DEV in r$apply )
		{
		if ( result?$variance )
			result$std_dev = sqrt(result$variance);
		}
	}

hook compose_resultvals_hook(result: Result, rv1: Result, rv2: Result) &priority=-10
	{
	if ( rv1?$sum || rv2?$sum )
		{
		result$sum = rv1?$sum ? rv1$sum : 0;
		if ( rv2?$sum )
			result$sum += rv2$sum;
		}
	}