
module Measurement;

export {
	redef enum Calculation += { 
		## Calculate the average of the values.
		AVERAGE
	};

	redef record Result += {
		## For numeric data, this calculates the average of all values.
		average: double &log &optional;
	};
}

hook add_to_reducer(r: Reducer, val: double, data: DataPoint, result: Result)
	{
	if ( AVERAGE in r$apply )
		{
		if ( ! result?$average ) 
			result$average = val;
		else
			result$average += (val - result$average) / result$num;
		}
	}

hook compose_resultvals_hook(result: Result, rv1: Result, rv2: Result)
	{
	if ( rv1?$average && rv2?$average )
		result$average = ((rv1$average*rv1$num) + (rv2$average*rv2$num))/(rv1$num+rv2$num);
	else if ( rv1?$average )
		result$average = rv1$average;
	else if ( rv2?$average )
		result$average = rv2$average;
	}