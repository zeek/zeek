##! A FIFO queue.

module Queue;

export {
	## Settings for initializing the queue.
	type Settings: record {
		## If a maximum length is set for the queue
		## it will maintain itself at that
		## maximum length automatically.
		max_len: count &optional;
	};

	## The internal data structure for the queue.
	type Queue: record {};

	## Initialize a queue record structure.
	##
	## s: A record which configures the queue.
	##
	## Returns: An opaque queue record.
	global init:       function(s: Settings &default=[]): Queue;

	## Put a value onto the beginning of a queue.
	##
	## q: The queue to put the value into.
	##
	## val: The value to insert into the queue.
	global put:       function(q: Queue, val: any);

	## Get a value from the end of a queue.
	##
	## q: The queue to get the value from.
	##
	## Returns: The value gotten from the queue.
	global get:        function(q: Queue): any;

	## Peek at the value at the end of the queue without removing it.
	##
	## q: The queue to get the value from.
	##
	## Returns: The value at the end of the queue.
	global peek:      function(q: Queue): any;

	## Merge two queues together.  If any settings are applied
	## to the queues, the settings from *q1* are used for the new
	## merged queue.
	##
	## q1: The first queue.  Settings are taken from here.
	##
	## q2: The second queue.
	##
	## Returns: A new queue from merging the other two together.
	global merge:      function(q1: Queue, q2: Queue): Queue;

	## Get the number of items in a queue.
	##
	## q: The queue.
	##
	## Returns: The length of the queue.
	global len:     function(q: Queue): count;

	## Get the contents of the queue as a vector.
	##
	## q: The queue.
	##
	## ret: A vector containing the current contents of the queue
	##      as the type of ret.
	global get_vector: function(q: Queue, ret: vector of any);

}

redef record Queue += {
	# The values are stored here.
	vals:        list of any &optional;

	# Settings for the queue.
	settings:    Settings               &optional;
};

function init(s: Settings): Queue
	{
	return Queue($vals=list(), $settings=copy(s));
	}

function put(q: Queue, val: any)
	{
	if ( q$settings?$max_len && |q$vals| >= q$settings$max_len )
		--q$vals;

	q$vals += val;
	}

function get(q: Queue): any
	{
	return --q$vals;
	}

function peek(q: Queue): any
	{
	return q$vals[0];
	}

function merge(q1: Queue, q2: Queue): Queue
	{
	local ret = init(q1$settings);
	ret$vals += q1;
	ret$vals += q2;
	return ret;
	}

function len(q: Queue): count
	{
	return |q$vals|;
	}

function get_vector(q: Queue, ret: vector of any)
	{
	for ( i in q$vals )
		ret += i;
	}
