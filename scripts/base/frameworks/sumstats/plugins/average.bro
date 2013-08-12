@load ../main

module SumStats;

export {
	redef enum Calculation += {
		## Calculate the average of the values.
		AVERAGE
	};

	redef record ResultVal += {
		## For numeric data, this calculates the average of all values.
		average: double &optional;
	};
}

hook register_observe_plugins()
	{
	register_observe_plugin(AVERAGE, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( ! rv?$average )
			rv$average = val;
		else
			rv$average += (val - rv$average) / rv$num;
		});
	}


hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$average && rv2?$average )
		result$average = ((rv1$average*rv1$num) + (rv2$average*rv2$num))/(rv1$num+rv2$num);
	else if ( rv1?$average )
		result$average = rv1$average;
	else if ( rv2?$average )
		result$average = rv2$average;
	}
