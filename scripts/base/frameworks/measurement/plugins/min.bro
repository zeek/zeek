
module Measurement;

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

hook add_to_reducer_hook(r: Reducer, val: double, data: DataPoint, rv: ResultVal)
	{
	if ( MIN in r$apply )
		{
		if ( ! rv?$min ) 
			rv$min = val;
		else if ( val < rv$min )
			rv$min = val;
		}
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