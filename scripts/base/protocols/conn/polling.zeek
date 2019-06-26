##! Implements a generic way to poll connections looking for certain features
##! (e.g. monitor bytes transferred).  The specific feature of a connection
##! to look for, the polling interval, and the code to execute if the feature
##! is found are all controlled by user-defined callback functions.

module ConnPolling;

export {
	## Starts monitoring a given connection.
	##
	## c: The connection to watch.
	##
	## callback: A callback function that takes as arguments the monitored
	##           *connection*, and counter *cnt* that increments each time
	##           the callback is called.  It returns an interval indicating
	##           how long in the future to schedule an event which will call
	##           the callback.  A negative return interval causes polling
	##           to stop.
	##
	## cnt: The initial value of a counter which gets passed to *callback*.
	##
	## i: The initial interval at which to schedule the next callback.
	##    May be ``0secs`` to poll right away.
	global watch: function(c: connection,
			       callback: function(c: connection, cnt: count): interval,
			       cnt: count, i: interval);
}

event ConnPolling::check(c: connection,
			 callback: function(c: connection, cnt: count): interval,
			 cnt: count)
	{
	if ( ! connection_exists(c$id) )
		return;

	lookup_connection(c$id); # updates the conn val

	local next_interval = callback(c, cnt);
	if ( next_interval < 0secs )
		return;

	watch(c, callback, cnt + 1, next_interval);
	}

function watch(c: connection,
	       callback: function(c: connection, cnt: count): interval,
	       cnt: count, i: interval)
	{
	schedule i { ConnPolling::check(c, callback, cnt) };
	}
