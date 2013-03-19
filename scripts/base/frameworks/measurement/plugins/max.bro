
module Measurement;

export {
	redef enum Calculation += { 
		## Find the maximum value.
		MAX
	};

	redef record Result += {
		## For numeric data, this tracks the maximum value given.
		max:      double        &log &optional;
	};
}

hook add_to_reducer(r: Reducer, val: double, data: DataPoint, result: Result)
	{
	if ( MAX in r$apply )
		{
		if ( ! result?$max ) 
			result$max = val;
		else if ( val > result$max )
			result$max = val;
		}
	}

hook compose_resultvals_hook(result: Result, rv1: Result, rv2: Result)
	{
	if ( rv1?$max && rv2?$max )
		result$max = (rv1$max > rv2$max) ? rv1$max : rv2$max;
	else if ( rv1?$max )
		result$max = rv1$max;
	else if ( rv2?$max )
		result$max = rv2$max;
	}


