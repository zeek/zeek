@load base/frameworks/sumstats

event connection_established(c: connection)
	{
	# Make an observation!
	# This observation is global so the key is empty.
	# Each established connection counts as one so the observation is always 1.
	SumStats::observe("conn established", 
	                  SumStats::Key(), 
	                  SumStats::Observation($num=1));
	}

event zeek_init()
	{
	# Create the reducer.
	# The reducer attaches to the "conn established" observation stream
	# and uses the summing calculation on the observations.
	local r1 = SumStats::Reducer($stream="conn established", 
	                             $apply=set(SumStats::SUM));

	# Create the final sumstat.
	# We give it an arbitrary name and make it collect data every minute.
	# The reducer is then attached and a $epoch_result callback is given 
	# to finally do something with the data collected.
	SumStats::create([$name = "counting connections",
	                  $epoch = 1min,
	                  $reducers = set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	# This is the body of the callback that is called when a single 
	                  	# result has been collected.  We are just printing the total number
	                  	# of connections that were seen.  The $sum field is provided as a 
	                  	# double type value so we need to use %f as the format specifier.
	                  	print fmt("Number of connections established: %.0f", result["conn established"]$sum);
	                  	}]);
	}
