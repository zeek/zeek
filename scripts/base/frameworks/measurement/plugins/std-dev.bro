@load ./variance
@load base/frameworks/measurement

module Measurement;

export {
	redef enum Calculation += { 
		## Find the standard deviation of the values.
		STD_DEV
	};

	redef record ResultVal += {
		## For numeric data, this calculates the standard deviation.
		std_dev: double &optional;
	};
}

function calc_std_dev(rv: ResultVal)
	{
	if ( rv?$variance )
		rv$std_dev = sqrt(rv$variance);
	}

# This depends on the variance plugin which uses priority -5
hook add_to_reducer_hook(r: Reducer, val: double, data: DataPoint, rv: ResultVal) &priority=-10
	{
	if ( STD_DEV in r$apply )
		{
		if ( rv?$variance )
			calc_std_dev(rv);
		else
			rv$std_dev = 0.0;
		}
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal) &priority=-10
	{
	calc_std_dev(result);
	}
