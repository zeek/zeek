@load base/frameworks/sumstats

# We use the connection_attempt event to limit our observations to those
# which were attempted and not successful.
event connection_attempt(c: connection)
	{
	# Make an observation!
	# This observation is about the host attempting the connection.
	# Each established connection counts as one so the observation is always 1.
	SumStats::observe("conn attempted", 
	                  SumStats::Key($host=c$id$orig_h), 
	                  SumStats::Observation($num=1));
	}

event bro_init()
	{
	# Create the reducer.
	# The reducer attaches to the "conn attempted" observation stream
	# and uses the summing calculation on the observations. Keep
	# in mind that there will be one result per key (connection originator).
	local r1 = SumStats::Reducer($stream="conn attempted", 
	                             $apply=set(SumStats::SUM));

	# Create the final sumstat.
	# This is slightly different from the last example since we're providing
	# a callback to calculate a value to check against the threshold with 
	# $threshold_val.  The actual threshold itself is provided with $threshold.
	# Another callback is provided for when a key crosses the threshold.
	SumStats::create([$name = "finding scanners",
	                  $epoch = 5min,
	                  $reducers = set(r1),
	                  # Provide a threshold.
	                  $threshold = 5.0,
	                  # Provide a callback to calculate a value from the result
	                  # to check against the threshold field.
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["conn attempted"]$sum;
	                  	},
	                  # Provide a callback for when a key crosses the threshold.
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	print fmt("%s attempted %.0f or more connections", key$host, result["conn attempted"]$sum);
	                  	}]);
	}
