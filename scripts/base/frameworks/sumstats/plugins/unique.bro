@load base/frameworks/sumstats

module SumStats;

export {
	redef enum Calculation += {
		## Calculate the number of unique values.
		UNIQUE
	};

	redef record ResultVal += {
		## If cardinality is being tracked, the number of unique
		## items is tracked here.
		unique: count &default=0;
	};
}

redef record ResultVal += {
	# Internal use only.  This is not meant to be publically available
	# because we don't want to trust that we can inspect the values
	# since we will like move to a probalistic data structure in the future.
	# TODO: in the future this will optionally be a hyperloglog structure
	unique_vals: set[Observation] &optional;
};

hook observe_hook(r: Reducer, val: double, obs: Observation, rv: ResultVal)
	{
	if ( UNIQUE in r$apply )
		{
		if ( ! rv?$unique_vals )
			rv$unique_vals=set();
		add rv$unique_vals[obs];
		rv$unique = |rv$unique_vals|;
		}
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$unique_vals || rv2?$unique_vals )
		{
		if ( rv1?$unique_vals )
			result$unique_vals = rv1$unique_vals;

		if ( rv2?$unique_vals )
			if ( ! result?$unique_vals )
				result$unique_vals = rv2$unique_vals;
			else
				for ( val2 in rv2$unique_vals )
					add result$unique_vals[val2];

		result$unique = |result$unique_vals|;
		}
	}
