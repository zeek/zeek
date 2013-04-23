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


