@load base/frameworks/sumstats/main
@load base/utils/queue

module SumStats;

export {
	redef record Reducer += {
		## A number of sample Observations to collect.
		samples: count &default=0;
	};

	redef record ResultVal += {
		## This is the queue where samples are maintained.  Use the
		## :bro:see:`SumStats::get_samples` function to get a vector of the samples.
		samples: Queue::Queue &optional;
	};

	## Get a vector of sample Observation values from a ResultVal.
	global get_samples: function(rv: ResultVal): vector of Observation;
}

function get_samples(rv: ResultVal): vector of Observation
	{
	local s: vector of Observation = vector();
	if ( rv?$samples )
		Queue::get_vector(rv$samples, s);
	return s;
	}

hook observe_hook(r: Reducer, val: double, obs: Observation, rv: ResultVal)
	{
	if ( r$samples > 0 )
		{
		if ( ! rv?$samples )
			rv$samples = Queue::init([$max_len=r$samples]);
		Queue::put(rv$samples, obs);
		}
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	# Merge $samples
	if ( rv1?$samples && rv2?$samples )
		result$samples = Queue::merge(rv1$samples, rv2$samples);
	else if ( rv1?$samples )
		result$samples = rv1$samples;
	else if ( rv2?$samples )
		result$samples = rv2$samples;
	}
