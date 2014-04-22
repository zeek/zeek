@load ./variance
@load ../main

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

hook std_dev_hook(r: Reducer, val: double, obs: Observation, rv: ResultVal)
	{
	calc_std_dev(rv);
	}

hook register_observe_plugins() &priority=-10
	{
	register_observe_plugin(STD_DEV, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		calc_std_dev(rv);
		});
	add_observe_plugin_dependency(STD_DEV, VARIANCE);
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal) &priority=-10
	{
	calc_std_dev(result);
	}
