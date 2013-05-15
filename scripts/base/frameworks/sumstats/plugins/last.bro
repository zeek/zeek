@load base/frameworks/sumstats
@load base/utils/queue

module SumStats;

export {
	redef enum Calculation += {
		## Keep last X observations in Queue
		LAST
	};

	redef record Reducer += {
		## number of elements to keep.
		num_last_elements: count &default=0;
	};

	redef record ResultVal += {
		## This is the queue where elements are maintained.  Use the
		## :bro:see:`SumStats::get_elements` function to get a vector of the samples.
		last_elements: Queue::Queue &optional;
	};

	## Get a vector of element values from a ResultVal.
	global get_elements: function(rv: ResultVal): vector of Observation;
}

function get_elements(rv: ResultVal): vector of Observation
	{
	local s: vector of Observation = vector();
	if ( rv?$last_elements )
		Queue::get_vector(rv$last_elements, s);
	return s;
	}

hook observe_hook(r: Reducer, val: double, obs: Observation, rv: ResultVal)
	{
	if ( LAST in r$apply && r$num_last_elements > 0 )
		{
		if ( ! rv?$last_elements )
			rv$last_elements = Queue::init([$max_len=r$num_last_elements]);
		Queue::put(rv$last_elements, obs);
		}
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
