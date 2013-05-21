@load ./average
@load ../main

module SumStats;

export {
	redef enum Calculation += {
		## Find the variance of the values.
		VARIANCE
	};

	redef record ResultVal += {
		## For numeric data, this calculates the variance.
		variance: double &optional;
	};
}

redef record ResultVal += {
	# Internal use only.  Used for incrementally calculating variance.
	prev_avg: double &optional;

	# Internal use only.  For calculating incremental variance.
	var_s: double &default=0.0;
};

function calc_variance(rv: ResultVal)
	{
	rv$variance = (rv$num > 1) ? rv$var_s/(rv$num-1) : 0.0;
	}

hook register_observe_plugins() &priority=-5
	{
	register_observe_plugin(VARIANCE, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( rv$num > 1 )
			rv$var_s += ((val - rv$prev_avg) * (val - rv$average));

		calc_variance(rv);
		rv$prev_avg = rv$average;
		});
	add_observe_plugin_dependency(VARIANCE, AVERAGE);
	}

# Reduced priority since this depends on the average
hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal) &priority=-5
	{
	if ( rv1?$var_s && rv1?$average &&
	     rv2?$var_s && rv2?$average )
		{
		local rv1_avg_sq = (rv1$average - result$average);
		rv1_avg_sq = rv1_avg_sq*rv1_avg_sq;
		local rv2_avg_sq = (rv2$average - result$average);
		rv2_avg_sq = rv2_avg_sq*rv2_avg_sq;
		result$var_s = rv1$num*(rv1$var_s/rv1$num + rv1_avg_sq) + rv2$num*(rv2$var_s/rv2$num + rv2_avg_sq);
		}
	else if ( rv1?$var_s )
		result$var_s = rv1$var_s;
	else if ( rv2?$var_s )
		result$var_s = rv2$var_s;

	if ( rv1?$prev_avg && rv2?$prev_avg )
		result$prev_avg = ((rv1$prev_avg*rv1$num) + (rv2$prev_avg*rv2$num))/(rv1$num+rv2$num);
	else if ( rv1?$prev_avg )
		result$prev_avg = rv1$prev_avg;
	else if ( rv2?$prev_avg )
		result$prev_avg = rv2$prev_avg;

	calc_variance(result);
	}
