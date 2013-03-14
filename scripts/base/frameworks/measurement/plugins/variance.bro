@load ./average

module Metrics;

export {
	redef enum Calculation += { 
		## Find the variance of the values.
		VARIANCE
	};

	redef record ResultVal += {
		## For numeric data, this calculates the variance.
		variance: double &log &optional;
	};
}

redef record ResultVal += {
	# Internal use only.  Used for incrementally calculating variance.
	prev_avg: double &optional;

	# Internal use only.  For calculating incremental variance.
	var_s: double &optional;
};

hook add_to_calculation(filter: Filter, val: double, data: DataPoint, result: ResultVal) &priority=5
	{
	if ( VARIANCE in filter$measure )
		result$prev_avg = result$average;
	}

# Reduced priority since this depends on the average
hook add_to_calculation(filter: Filter, val: double, data: DataPoint, result: ResultVal) &priority=-5
	{
	if ( VARIANCE in filter$measure )
		{
		if ( ! result?$var_s )
			result$var_s = 0.0;
		result$var_s += (val - result$prev_avg) * (val - result$average);
		result$variance = (val > 0) ? result$var_s/val : 0.0;
		}
	}

# Reduced priority since this depends on the average
hook plugin_merge_measurements(result: ResultVal, rv1: ResultVal, rv2: ResultVal) &priority=-5
	{
	if ( rv1?$var_s && rv2?$var_s )
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
	}