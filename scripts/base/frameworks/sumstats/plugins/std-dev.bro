@load base/frameworks/sumstats/main
@load ./variance

module SumStats;

export {
	redef enum Calculation += {
		## Find the standard deviation of the values.
		STD_DEV
	};

	redef record ResultVal += {
		## For numeric data, this calculates the standard deviation.
		std_dev: double &default=0.0;
	};
}

function calc_std_dev(rv: ResultVal)
	{
	if ( rv?$variance )
		rv$std_dev = sqrt(rv$variance);
	}

# This depends on the variance plugin which uses priority -5
hook observe_hook(r: Reducer, val: double, obs: Observation, rv: ResultVal) &priority=-10
	{
	if ( STD_DEV in r$apply )
		calc_std_dev(rv);
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal) &priority=-10
	{
	calc_std_dev(result);
	}
