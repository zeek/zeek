##! Keep the last X observations.

@load base/frameworks/sumstats
@load base/utils/queue

module SumStats;

export {
	redef enum Calculation += {
		## Keep last X observations in a queue.
		LAST
	};

	redef record Reducer += {
		## Number of elements to keep.
		num_last_elements: count &default=0;
	};

	redef record ResultVal += {
		## This is the queue where elements are maintained.
		## Don't access this value directly, instead use the
		## :zeek:see:`SumStats::get_last` function to get a vector of
		## the current element values.
		last_elements: Queue::Queue &optional;
	};

	## Get a vector of element values from a ResultVal.
	global get_last: function(rv: ResultVal): vector of Observation;
}

function get_last(rv: ResultVal): vector of Observation
	{
	local s: vector of any = vector();

	if ( rv?$last_elements )
		Queue::get_vector(rv$last_elements, s);

	local rval: vector of Observation = vector();

	for ( i in s )
		# When using the cluster-ized version of SumStats, Queue's
		# internal table storage uses "any" type for values, so we need
		# to cast them here or else they may be left as Broker::Data from
		# the unserialization process.
		rval += s[i] as Observation;

	return rval;
	}

hook register_observe_plugins()
	{
	register_observe_plugin(LAST, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( r$num_last_elements > 0 )
			{
			if ( ! rv?$last_elements )
				rv$last_elements = Queue::init([$max_len=r$num_last_elements]);
			Queue::put(rv$last_elements, obs);
			}
		});
	}


hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	# Merge $samples
	if ( rv1?$last_elements && rv2?$last_elements )
		result$last_elements = Queue::merge(rv1$last_elements, rv2$last_elements);
	else if ( rv1?$last_elements )
		result$last_elements = rv1$last_elements;
	else if ( rv2?$last_elements )
		result$last_elements = rv2$last_elements;
	}
