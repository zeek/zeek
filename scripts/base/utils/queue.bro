##! A FIFO string queue.

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
	## s: A :bro:record:`Settings` record configuring the queue.
	##
	## Returns: An opaque queue record.
	global init:       function(s: Settings): Queue;

	## Push a string onto the top of a queue.
	## 
	## q: The queue to push the string into.
	## 
	## val: The string to push 
	global push:       function(q: Queue, val: any);

	## Pop a string from the bottom of a queue.
	##
	## q: The queue to pop the string from.
	##
	## Returns: The string popped from the queue.
	global pop:        function(q: Queue): any;

	## Merge two queue's together.  If any settings are applied 
	## to the queues, the settings from q1 are used for the new
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
	
	## Get the contents of the queue as a string vector.
	## 
	## q: The queue.
	##
	## Returns: A :bro:type:`vector of string` containing the 
	##          current contents of q.
	global get_str_vector: function(q: Queue): vector of string;

	## Get the contents of the queue as a count vector.  Use care
	## with this function.  If the data put into the queue wasn't 
	## integers you will get conversion errors.
	## 
	## q: The queue.
	##
	## Returns: A :bro:type:`vector of count` containing the 
	##          current contents of q.
	global get_cnt_vector: function(q: Queue): vector of count;
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

function push(q: Queue, val: any)
	{
	if ( q$settings?$max_len && len(q) >= q$settings$max_len )
		pop(q);
	q$vals[q$top] = val;
	++q$top;
	}

function pop(q: Queue): any
	{
	local ret = q$vals[q$bottom];
	delete q$vals[q$bottom];
	++q$bottom;
	return ret;
	}

function merge(q1: Queue, q2: Queue): Queue
	{
	local ret = init(q1$settings);
	local i = q1$bottom;
	local j = q2$bottom;
	for ( ignored_val in q1$vals )
		{
		if ( i in q1$vals )
			push(ret, q1$vals[i]);
		if ( j in q2$vals )
			push(ret, q2$vals[j]);
		++i;
		++j;
		}
	}

function len(q: Queue): count
	{
	return |q$vals|;
	}

function get_str_vector(q: Queue): vector of string
	{
	local ret: vector of string;
	local i = q$bottom;
	local j = 0;
	# Really dumb hack, this is only to provide
	# the iteration for the correct number of 
	# values in q$vals.
	for ( ignored_val in q$vals )
		{
		if ( i >= q$top )
			break;

		ret[j] = cat(q$vals[i]);
		++j; ++i;
		}
	return ret;
	}

function get_cnt_vector(q: Queue): vector of count
	{
	local ret: vector of count;
	local i = q$bottom;
	local j = 0;
	# Really dumb hack, this is only to provide
	# the iteration for the correct number of 
	# values in q$vals.
	for ( ignored_val in q$vals )
		{
		if ( i >= q$top )
			break;

		# TODO: this is terrible and should be replaced by 
		#       a more generic version of the various 
		#       functions to get vectors of values.
		#       (the way "any" works right now makes this impossible though)
		ret[j] = to_count(cat(q$vals[i]));
		++j; ++i;
		}
	return ret;
	}

