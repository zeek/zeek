##! The BatchQueue type is a queue of any elements which is flushed
##! when reaching a maximum size, or when the age of the oldest element
##! exceeds max delay. Flushing invokes a user-provided callback which
##! can then be used to further process the elements.
##!
##! You can use this queue when you have 1000s of data points per second
##! that need to be published in a cluster and can afford some amount of
##! latency in order to reduce pressure on the cluster backend. For example,
##! instead for publishing 100.000 data points per second separately, a batch
##! queue with a 10msec delay can reduce the publish rate by a factor 1000x
##! to 100 per second at only a 10msec delay. Each batch then contains about
##! 1000 data points. This can significantly reduce the per-publish overhead
##! and also help downstream consumers to work in a batched and potentially
##! more efficient fashion.
##!
##! A small optimization for low-rate batch queues is that a :zeek:see:`batch_queue_add`
##! will result in an immediate flush if the previous flush has happened more than
##! max_delay ago. The timer is based on Zeek's network time.
##!
##! Usage
##!
##!     local bq = batch_queue_new(
##!         $max_size=1000,
##!         $max_delay=10msec,
##!         $flush_callback=function(bq: BatchQueue, elements: vector of any)
##!             {
##!             print(fmt("flushing %d element", |elements|));
##!             Cluster::publish(Cluster::manager_topic, batch_count_event, elements as vector of count);
##!             }
##!     );
##!
##!     batch_queue_add(bq, 42);  # flushes immediately
##!     batch_queue_add(bq, 4711);
##!     batch_queue_add(bq, 424711);
##!     ...
##!     # flush after about ~10msec
##!
##!     # Or call batch_queue_flush by hand:
##!     batch_queue_flush(bq);
##!
##!
##! Related
##!
##! TCP Nagle. In Spark Streaming this pattern is called "micro-batching".
##! In Kafka it's called "buffered flush" or "batch accumulator".
module GLOBAL;

type BatchQueue: record {
	max_size: count &default=100;
	max_delay: interval &default=10msec;
	elements: vector of any;
	timer_scheduled: bool &default=F;
	last_flush_at: time &default=double_to_time(0.0);
};

type BatchQueueFlushCallback: function(bq: BatchQueue, elements: vector of any);

redef record BatchQueue += {
	flush_callback: BatchQueueFlushCallback &default=function(bq: BatchQueue, elements: vector of any) { };
};

function batch_queue_new(max_size: count, max_delay: interval, flush_callback: BatchQueueFlushCallback): BatchQueue
	{
	return BatchQueue(
		$max_size=max_size,
		$max_delay=max_delay,
		$flush_callback=flush_callback,
	);
	}

function batch_queue_flush(bq: BatchQueue)
	{
	bq$flush_callback(bq, bq$elements);
	bq$elements = vector();
	bq$last_flush_at = network_time();
	}

event batch_queue_timer_expired(bq: BatchQueue)
	{
	bq$timer_scheduled = F;

	# Even if there was a flush inbetween, if any more
	# elements have been queued, flush them now.
	if ( |bq$elements| > 0)
		batch_queue_flush(bq);
	}

function batch_queue_add(bq: BatchQueue, element: any)
	{
	local now = network_time();

	bq$elements += element;

	if ( bq$max_size > 0 && |bq$elements| >= bq$max_size )
		{
		# If a non-zero max_size is set and it's been reached, flush
		# the queue now, including the just queued elemment.
		batch_queue_flush(bq);
		}
	else if ( |bq$elements| == 1 && now > (bq$last_flush_at + bq$max_delay) )
		{
		# If this was the first element and the last publish happened
		# longer than max_delay ago, flush that one element directly
		# to reduce once-in-a-while queueing delays.
		batch_queue_flush(bq);
		}
	else if ( ! bq$timer_scheduled )
		{
		# Otherwise, if there hasn't been a timer scheduled for
		# this queue yet, do it now.
		schedule bq$max_delay { batch_queue_timer_expired(bq) };
		bq$timer_scheduled = T;
		}
	}
