@load ../main

module SumStats;

export {
	redef enum Calculation += {
		## Find the minimum value.
		MIN
	};

	redef record ResultVal += {
		## For numeric data, this tracks the minimum value given.
		min: double &optional;
	};
}

hook register_observe_plugins()
	{
	register_observe_plugin(MIN, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( ! rv?$min )
			rv$min = val;
		else if ( val < rv$min )
			rv$min = val;
		});
	}


hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$min && rv2?$min )
		result$min = (rv1$min < rv2$min) ? rv1$min : rv2$min;
	else if ( rv1?$min )
		result$min = rv1$min;
	else if ( rv2?$min )
		result$min = rv2$min;
	}
