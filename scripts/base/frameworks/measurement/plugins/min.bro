
module Measurement;

export {
	redef enum Calculation += { 
		## Find the minimum value.
		MIN
	};

	redef record Result += {
		## For numeric data, this tracks the minimum value given.
		min:      double        &log &optional;
	};
}

hook add_to_reducer(r: Reducer, val: double, data: DataPoint, result: Result)
	{
	if ( MIN in r$apply )
		{
		if ( ! result?$min ) 
			result$min = val;
		else if ( val < result$min )
			result$min = val;
		}
	}

hook compose_resultvals_hook(result: Result, rv1: Result, rv2: Result)
	{
	if ( rv1?$min && rv2?$min )
		result$min = (rv1$min < rv2$min) ? rv1$min : rv2$min;
	else if ( rv1?$min )
		result$min = rv1$min;
	else if ( rv2?$min )
		result$min = rv2$min;
	}