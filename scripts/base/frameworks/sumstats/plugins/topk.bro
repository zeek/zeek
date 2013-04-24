@load base/frameworks/sumstats

module SumStats;

export {
	redef record Reducer += {
		## number of elements to keep in the top-k list
		topk_size: count &default=500;
	};

	redef enum Calculation += {
		TOPK
	};

	redef record ResultVal += {
		topk: opaque of topk &optional;
	};

}

hook init_resultval_hook(r: Reducer, rv: ResultVal)
	{
	if ( TOPK in r$apply && ! rv?$topk )
		rv$topk = topk_init(r$topk_size);
	}

hook observe_hook(r: Reducer, val: double, obs: Observation, rv: ResultVal)
	{
	if ( TOPK in r$apply ) 
		{
		topk_add(rv$topk, obs);
		}
	}


hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	result$topk = topk_init(topk_size(rv1$topk));

	topk_merge(result$topk, rv1$topk);
	topk_merge(result$topk, rv2$topk);
	}
