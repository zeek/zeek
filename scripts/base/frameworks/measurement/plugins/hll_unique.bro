
module Measurement;

export {
	redef enum Calculation += { 
		## Calculate the number of unique values.
		HLLUNIQUE
	};

	redef record ResultVal += {
		## If cardinality is being tracked, the number of unique
		## items is tracked here.
		hllunique: opaque of cardinality &default=hll_cardinality_init(0.01);
	};
}

hook init_resultval_hook(r: Reducer, rv: ResultVal)
	{
	if ( HLLUNIQUE in r$apply && ! rv?$hllunique )
		rv$hllunique = hll_cardinality_init(0.01);
	}


hook add_to_reducer_hook(r: Reducer, val: double, data: DataPoint, rv: ResultVal)
	{
	if ( HLLUNIQUE in r$apply )
		{
		hll_cardinality_add(rv$hllunique, data);
		}
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	local rhll = hll_cardinality_init(0.01);
	hll_cardinality_merge_into(rhll, rv1$hllunique);
	hll_cardinality_merge_into(rhll, rv2$hllunique);

	result$hllunique = rhll;
	}
