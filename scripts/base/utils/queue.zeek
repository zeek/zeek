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
	# Indicator for if the queue was appropriately initialized.
	initialized: bool                   &default=F;
	# The values are stored here.
	vals:        table[count] of any &optional;
	# Settings for the queue.
	settings:    Settings               &optional;
	# The top value in the vals table.
	top:         count                  &default=0;
	# The bottom value in the vals table.
	bottom:      count                  &default=0;
	# The number of bytes in the queue.
	size:        count                  &default=0;
};

function init(s: Settings): Queue
	{
	local q: Queue;
	q$vals=table();
	q$settings = copy(s);
	q$initialized=T;
	return q;
	}

function put(q: Queue, val: any)
	{
	if ( q$settings?$max_len && len(q) >= q$settings$max_len )
		get(q);
	q$vals[q$top] = val;
	++q$top;
	}

function get(q: Queue): any
	{
	local ret = q$vals[q$bottom];
	delete q$vals[q$bottom];
	++q$bottom;
	return ret;
	}

function peek(q: Queue): any
	{
	return q$vals[q$bottom];
	}

function merge(q1: Queue, q2: Queue): Queue
	{
	local ret = init(q1$settings);
	local i = q1$bottom;
	local j = q2$bottom;
	for ( ignored_val in q1$vals )
		{
		if ( i in q1$vals )
			put(ret, q1$vals[i]);
		if ( j in q2$vals )
			put(ret, q2$vals[j]);
		++i;
		++j;
		}
	return ret;
	}

function len(q: Queue): count
	{
	return |q$vals|;
	}

function get_vector(q: Queue, ret: vector of any)
	{
	local i = q$bottom;
	local j = 0;
	# Really dumb hack, this is only to provide
	# the iteration for the correct number of
	# values in q$vals.
	for ( ignored_val in q$vals )
		{
		if ( i >= q$top )
			break;

		ret[j] = q$vals[i];
		++j; ++i;
		}
	}
