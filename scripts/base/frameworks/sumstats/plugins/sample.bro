@load base/frameworks/sumstats/main

module SumStats;

export {
	redef enum Calculation += {
		## Get uniquely distributed random samples from the observation
		## stream.
		SAMPLE
	};

	redef record Reducer += {
		## A number of sample Observations to collect.
		num_samples: count &default=0;
	};

	redef record ResultVal += {
		## This is the vector in which the samples are maintained.
		samples: vector of Observation &default=vector();

		## Number of total observed elements.
		sample_elements: count &default=0;
	};
}

redef record ResultVal += {
	# Internal use only.  This is not meant to be publically available
	# and just a copy of num_samples from the Reducer. Needed for
	# availability in the compose hook.
	num_samples: count &default=0;
};

hook init_resultval_hook(r: Reducer, rv: ResultVal)
	{
	if ( SAMPLE in r$apply )
		rv$num_samples = r$num_samples;
	}

function sample_add_sample(obs:Observation, rv: ResultVal)
	{
	++rv$sample_elements;

	if ( |rv$samples| < rv$num_samples )
		rv$samples[|rv$samples|] = obs;
	else
		{
		local ra = rand(rv$sample_elements);
		if ( ra < rv$num_samples )
			rv$samples[ra] = obs;
		}
	}

hook register_observe_plugins()
	{
	register_observe_plugin(SAMPLE, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		sample_add_sample(obs, rv);
		});
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1$num_samples != rv2$num_samples )
		{
		Reporter::error("Merging sample sets with differing sizes is not supported");
		return;
		}

	local num_samples = rv1$num_samples;
	result$num_samples = num_samples;

	if ( |rv1$samples| > num_samples || |rv2$samples| > num_samples )
		{
		Reporter::error("Sample vector with too many elements. Aborting.");
		return;
		}

	if ( |rv1$samples| != num_samples && |rv2$samples| < num_samples )
		{
		if ( |rv1$samples| != rv1$sample_elements || |rv2$samples| < rv2$sample_elements )
			{
			Reporter::error("Mismatch in sample element size and tracking. Aborting merge");
			return;
			}

		for ( i in rv1$samples )
			sample_add_sample(rv1$samples[i], result);

		for ( i in rv2$samples)
			sample_add_sample(rv2$samples[i], result);
		}
	else
		{
		local other_vector: vector of Observation;
		local othercount: count;
		
		if ( rv1$sample_elements > rv2$sample_elements )
			{
			result$samples = copy(rv1$samples);
			other_vector = rv2$samples;
			othercount = rv2$sample_elements;
			}
		else
			{
			result$samples = copy(rv2$samples);
			other_vector = rv1$samples;
			othercount = rv1$sample_elements;
			}

		local totalcount = rv1$sample_elements + rv2$sample_elements;
		result$sample_elements = totalcount;

		for ( i in other_vector )
			{
			if ( rand(totalcount) <= othercount )
				result$samples[i] = other_vector[i];
			}
		}
	}
