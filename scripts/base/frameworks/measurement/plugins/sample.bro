
module Measurement;

export {
	
	redef record Reducer += {
		## A number of sample DataPoints to collect.
		samples: count &default=0;
	};

	redef record ResultVal += {
		## A sample of something being measured.  This is helpful in 
		## some cases for collecting information to do further detection
		## or better logging for forensic purposes.
		samples: vector of Measurement::DataPoint &optional;
	};
}

redef record ResultVal += {
	# Internal use only.  This is the queue where samples
	# are maintained since the queue is self managing for
	# the number of samples requested.
	sample_queue: Queue::Queue &optional;
};

hook add_to_reducer_hook(r: Reducer, val: double, data: DataPoint, rv: ResultVal)
	{
	if ( r$samples > 0 )
		{
		if ( ! rv?$sample_queue )
			rv$sample_queue = Queue::init([$max_len=r$samples]);
		Queue::push(rv$sample_queue, data$str);
		}
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	# Merge $sample_queue
	if ( rv1?$sample_queue && rv2?$sample_queue )
		result$sample_queue = Queue::merge(rv1$sample_queue, rv2$sample_queue);
	else if ( rv1?$sample_queue )
		result$sample_queue = rv1$sample_queue;
	else if ( rv2?$sample_queue )
		result$sample_queue = rv2$sample_queue;
	}