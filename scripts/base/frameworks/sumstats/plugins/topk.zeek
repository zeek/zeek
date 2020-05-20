##! Keep the top-k (i.e., most frequently occurring) observations.

@load base/frameworks/sumstats

module SumStats;

export {
	redef record Reducer += {
		## Number of elements to keep in the top-k list.
		topk_size: count &default=500;
	};

	redef enum Calculation += {
		## Keep a top-k list of values.
		TOPK
	};

	redef record ResultVal += {
		## A handle which can be passed to some built-in functions to get
		## the top-k results.
		topk: opaque of topk &optional;
	};

}

hook register_observe_plugins()
	{
	register_observe_plugin(TOPK, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		topk_add(rv$topk, obs);
		});
	}

hook init_resultval_hook(r: Reducer, rv: ResultVal)
	{
	if ( TOPK in r$apply && ! rv?$topk )
		rv$topk = topk_init(r$topk_size);
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$topk )
		{
		result$topk = topk_init(topk_size(rv1$topk));

		topk_merge(result$topk, rv1$topk);

		if ( rv2?$topk )
			topk_merge(result$topk, rv2$topk);
		}

	else if ( rv2?$topk )
		{
		result$topk = topk_init(topk_size(rv2$topk));
		topk_merge(result$topk, rv2$topk);
		}
	}
