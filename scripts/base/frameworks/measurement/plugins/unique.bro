
module Metrics;

export {
	redef enum Calculation += { 
		## Calculate the number of unique values.
		UNIQUE
	};

	redef record ResultVal += {
		## If cardinality is being tracked, the number of unique
		## items is tracked here.
		unique: count &log &optional;
	};
}

redef record ResultVal += {
	# Internal use only.  This is not meant to be publically available 
	# because we don't want to trust that we can inspect the values 
	# since we will like move to a probalistic data structure in the future.
	# TODO: in the future this will optionally be a hyperloglog structure
	unique_vals: set[DataPoint] &optional;
};

hook add_to_calculation(filter: Filter, val: double, data: DataPoint, result: ResultVal)
	{
	if ( UNIQUE in filter$measure )
		{
		if ( ! result?$unique_vals ) 
			result$unique_vals=set();
		add result$unique_vals[data];
		}
	}

hook plugin_merge_measurements(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
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