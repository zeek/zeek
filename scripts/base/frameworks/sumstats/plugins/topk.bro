@load base/frameworks/sumstats

module SumStats;

export {
	redef enum Calculation += {
		TOPK
	};

	redef record ResultVal += {
		topk: opaque of topk &default=topk_init(500);
	};

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
	result$topk = topk_init(500);

	topk_merge(result$topk, rv1$topk);
	topk_merge(result$topk, rv2$topk);
	}
