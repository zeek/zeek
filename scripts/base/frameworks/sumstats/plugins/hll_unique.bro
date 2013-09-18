@load base/frameworks/sumstats

module SumStats;

export {
	redef record Reducer += {
		## The error margin for HLL.
		hll_error_margin: double &default=0.01;

		## The confidence for HLL.
		hll_confidence: double &default=0.95;
	};

	redef enum Calculation += {
		## Calculate the number of unique values.
		HLL_UNIQUE
	};

	redef record ResultVal += {
		## If cardinality is being tracked, the number of unique
		## items is tracked here.
		hll_unique: count &default=0;
	};
}

redef record ResultVal += {
	# Internal use only.  This is not meant to be publically available
	# because probabilistic data structures have to be examined using
	# specialized bifs.
	card: opaque of cardinality &optional;

	# We need these in the compose hook.
	hll_error_margin: double &optional;
	hll_confidence: double &optional;
};

hook register_observe_plugins()
	{
	register_observe_plugin(HLL_UNIQUE, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( ! rv?$card )
			{
			rv$card = hll_cardinality_init(r$hll_error_margin, r$hll_confidence);
			rv$hll_error_margin = r$hll_error_margin;
			rv$hll_confidence = r$hll_confidence;
			}

		hll_cardinality_add(rv$card, obs);
		rv$hll_unique = double_to_count(hll_cardinality_estimate(rv$card));
		});
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( ! (rv1?$card || rv2?$card) )
		return;

	# Now at least one of rv1?$card or rv1?$card will be set, and
	# potentially both.

	local rhll: opaque of cardinality;

	if ( rv1?$card )
		{
		rhll = hll_cardinality_init(rv1$hll_error_margin, rv1$hll_confidence);
		hll_cardinality_merge_into(rhll, rv1$card);
		}
	else	# If we do not have rv1, we have to have rv2 ...
		rhll = hll_cardinality_init(rv2$hll_error_margin, rv2$hll_confidence);

	if ( rv2?$card )
		hll_cardinality_merge_into(rhll, rv2$card);

	result$card = rhll;
	result$hll_unique = double_to_count(hll_cardinality_estimate(rhll));
	}
