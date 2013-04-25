@load base/frameworks/sumstats

module SumStats;

export {
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
	card: opaque of cardinality &default=hll_cardinality_init(0.01);
};


hook init_resultval_hook(r: Reducer, rv: ResultVal)
	{
	if ( HLLUNIQUE in r$apply && ! rv?$card )
		rv$card = hll_cardinality_init(0.01);
		rv$hllunique = 0;
	}


hook observe_hook(r: Reducer, val: double, obs: Observation, rv: ResultVal)
	{
	if ( HLLUNIQUE in r$apply )
		{
		hll_cardinality_add(rv$card, obs);
		rv$hllunique = double_to_count(hll_cardinality_estimate(rv$card));
		}
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	local rhll = hll_cardinality_init(0.01);
	hll_cardinality_merge_into(rhll, rv1$card);
	hll_cardinality_merge_into(rhll, rv2$card);

	result$card = rhll;
	result$hllunique = double_to_count(hll_cardinality_estimate(rhll));
	}
