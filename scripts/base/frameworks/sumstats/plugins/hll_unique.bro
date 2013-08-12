@load base/frameworks/sumstats

module SumStats;

export {
	redef record Reducer += {
		## The threshold when we switch to hll
		hll_error_margin: double &default=0.01;
	};

	redef enum Calculation += { 
		## Calculate the number of unique values.
		HLLUNIQUE
	};

	redef record ResultVal += {
		## If cardinality is being tracked, the number of unique
		## items is tracked here.
		hllunique: count &default=0;
	};
}

redef record ResultVal += {
	# Internal use only.  This is not meant to be publically available 
	# because probabilistic data structures have to be examined using
	# specialized bifs.
	card: opaque of cardinality &optional;

	# we need this in the compose hook.
	hll_error_margin: double &optional;
};

hook register_observe_plugins()
	{
	register_observe_plugin(HLLUNIQUE, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( ! rv?$card )
			{
			rv$card = hll_cardinality_init(r$hll_error_margin);
			rv$hll_error_margin = r$hll_error_margin;
			rv$hllunique = 0;
			}

		hll_cardinality_add(rv$card, obs);
		rv$hllunique = double_to_count(hll_cardinality_estimate(rv$card));		
		});
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	local rhll = hll_cardinality_init(rv1$hll_error_margin);
	hll_cardinality_merge_into(rhll, rv1$card);
	hll_cardinality_merge_into(rhll, rv2$card);

	result$card = rhll;
	result$hllunique = double_to_count(hll_cardinality_estimate(rhll));
	}
