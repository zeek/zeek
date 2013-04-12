@load base/frameworks/measurement
@load base/utils/queue

module Measurement;

export {
	redef record Reducer += {
		## A number of sample DataPoints to collect.
		samples: count &default=0;
	};

	redef record ResultVal += {
		## This is the queue where samples
		## are maintained.  Use the 
		## :bro:see:`Measurement::get_samples` function
		## to get a vector of the samples.
		samples: Queue::Queue &optional;
	};

	## Get a vector of sample DataPoint values from a ResultVal.
	global get_samples: function(rv: ResultVal): vector of DataPoint;
}

function get_samples(rv: ResultVal): vector of DataPoint
	{
	local s: vector of DataPoint = vector();
	if ( rv?$samples )
		Queue::get_vector(rv$samples, s);
	return s;
	}

hook add_to_reducer_hook(r: Reducer, val: double, data: DataPoint, rv: ResultVal)
	{
	if ( r$samples > 0 )
		{
		if ( ! rv?$samples )
			rv$samples = Queue::init([$max_len=r$samples]);
		Queue::put(rv$samples, data);
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