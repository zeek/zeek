##! The summary statistics framework provides a way to 
##! summarize large streams of data into simple reduced 
##! measurements.

module SumStats;

export {
	## The various calculations are all defined as plugins.
	type Calculation: enum {
		PLACEHOLDER
	};

	## Represents a thing which is having summarization 
	## results collected for it.
	type Key: record {
		## A non-address related summarization or a sub-key for 
		## an address based summarization. An example might be 
		## successful SSH connections by client IP address
		## where the client string would be the key value.
		## Another example might be number of HTTP requests to 
		## a particular value in a Host header.  This is an 
		## example of a non-host based metric since multiple 
		## IP addresses could respond for the same Host 
		## header value.
		str:  string &optional;
	
		## Host is the value to which this metric applies.
		host: addr &optional;
	};
	
	## Represents data being added for a single observation.
	## Only supply a single field at a time!
	type Observation: record {
		## Count value.
		num:  count  &optional;
		## Double value.
		dbl:  double &optional;
		## String value.
		str:  string &optional;
	};

	type Reducer: record {
		## Observation stream identifier for the reducer 
		## to attach to.
		stream:         string;

		## The calculations to perform on the data points.
		apply:          set[Calculation];
		
		## A predicate so that you can decide per key if you 
		## would like to accept the data being inserted.
		pred:           function(key: SumStats::Key, obs: SumStats::Observation): bool &optional;
		
		## A function to normalize the key.  This can be used to aggregate or
		## normalize the entire key.
		normalize_key:  function(key: SumStats::Key): Key &optional;
	};

	## Value calculated for an observation stream fed into a reducer.
	## Most of the fields are added by plugins.
	type ResultVal: record {
		## The time when the first observation was added to 
		## this result value.
		begin:  time;

		## The time when the last observation was added to 
		## this result value.
		end:    time;

		## The number of observations received.
		num:    count &default=0;
	};

	## Type to store results for multiple reducers.
	type Result: table[string] of ResultVal;

	## Type to store a table of sumstats results indexed 
	## by keys.
	type ResultTable: table[Key] of Result;

	## SumStats represent an aggregation of reducers along with 
	## mechanisms to handle various situations like the epoch ending
	## or thresholds being crossed.
	## It's best to not access any global state outside 
	## of the variables given to the callbacks because there 
	## is no assurance provided as to where the callbacks 
	## will be executed on clusters.
	type SumStat: record {
		## The interval at which this filter should be "broken" 
		## and the '$epoch_finished' callback called.  The 
		## results are also reset at this time so any threshold
		## based detection needs to be set to a 
		## value that should be expected to happen within 
		## this epoch.
		epoch:              interval;

		## The reducers for the SumStat
		reducers:           set[Reducer];

		## Provide a function to calculate a value from the 
		## :bro:see:`Result` structure which will be used 
		## for thresholding.  
		## This is required if a $threshold value is given.
		threshold_val:      function(key: SumStats::Key, result: SumStats::Result): count &optional;

		## The threshold value for calling the 
		## $threshold_crossed callback.
		threshold:          count             &optional;
		
		## A series of thresholds for calling the 
		## $threshold_crossed callback.
		threshold_series:   vector of count   &optional;

		## A callback that is called when a threshold is crossed.
		threshold_crossed:  function(key: SumStats::Key, result: SumStats::Result) &optional;
		
		## A callback with the full collection of Results for 
		## this SumStat.
		epoch_finished:    function(rt: SumStats::ResultTable) &optional;
	};
	
	## Create a summary statistic.
	global create: function(ss: SumStats::SumStat);

	## Add data into an observation stream. This should be 
	## called when a script has measured some point value.
	##
	## id: The observation stream identifier that the data
	##     point represents.
	##
	## key: The key that the value is related to.
	##
	## obs: The data point to send into the stream.
	global observe: function(id: string, key: SumStats::Key, obs: SumStats::Observation);

	## This record is primarily used for internal threshold tracking.
	type Thresholding: record {
		# Internal use only.  Indicates if a simple threshold was already crossed.
		is_threshold_crossed: bool &default=F;

		# Internal use only.  Current key for threshold series.
		threshold_series_index: count &default=0;
	};

	## This event is generated when thresholds are reset for a SumStat.
	## 
	## ssid: SumStats ID that thresholds were reset for.
	global thresholds_reset: event(ssid: string);

	## Helper function to represent a :bro:type:`SumStats::Key` value as 
	## a simple string.
	## 
	## key: The metric key that is to be converted into a string.
	##
	## Returns: A string representation of the metric key.
	global key2str: function(key: SumStats::Key): string;
}

redef record Reducer += {
	# Internal use only.  Provides a reference back to the related SumStats by it's ID.
	sid: string &optional;
};

# Internal use only.  For tracking thresholds per sumstat and key.
global threshold_tracker: table[string] of table[Key] of Thresholding &optional;

redef record SumStat += {
	# Internal use only (mostly for cluster coherency).
	id: string &optional;
};

# Store of sumstats indexed on the sumstat id.
global stats_store: table[string] of SumStat = table();

# Store of reducers indexed on the data point stream id.
global reducer_store: table[string] of set[Reducer] = table();

# Store of results indexed on the measurement id.
global result_store: table[string] of ResultTable = table();

# Store of threshold information.
global thresholds_store: table[string, Key] of bool = table();

# This is called whenever
# key values are updated and the new val is given as the `val` argument.
# It's only prototyped here because cluster and non-cluster have separate 
# implementations.
global data_added: function(ss: SumStat, key: Key, result: Result);

# Prototype the hook point for plugins to do calculations.
global observe_hook: hook(r: Reducer, val: double, data: Observation, rv: ResultVal);
# Prototype the hook point for plugins to initialize any result values.
global init_resultval_hook: hook(r: Reducer, rv: ResultVal);
# Prototype the hook point for plugins to merge Results.
global compose_resultvals_hook: hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal);

# Event that is used to "finish" measurements and adapt the measurement
# framework for clustered or non-clustered usage.
global finish_epoch: event(ss: SumStat);

function key2str(key: Key): string
	{
	local out = "";
	if ( key?$host )
		out = fmt("%shost=%s", out, key$host);
	if ( key?$str )
		out = fmt("%s%sstr=%s", out, |out|==0 ? "" : ", ", key$str);
	return fmt("sumstats_key(%s)", out);
	}

function init_resultval(r: Reducer): ResultVal
	{
	local rv: ResultVal = [$begin=network_time(), $end=network_time()];
	hook init_resultval_hook(r, rv);
	return rv;
	}

function compose_resultvals(rv1: ResultVal, rv2: ResultVal): ResultVal
	{
	local result: ResultVal;

	result$begin = (rv1$begin < rv2$begin) ? rv1$begin : rv2$begin;
	result$end = (rv1$end > rv2$end) ? rv1$end : rv2$end;
	result$num = rv1$num + rv2$num;

	# Run the plugin composition hooks.
	hook compose_resultvals_hook(result, rv1, rv2);
	return result;
	}

function compose_results(r1: Result, r2: Result): Result
	{
	local result: Result = table();

	if ( |r1| > |r2| )
		{
		for ( data_id in r1 )
			{
			if ( data_id in r2 )
				result[data_id] = compose_resultvals(r1[data_id], r2[data_id]);
			else
				result[data_id] = r1[data_id];
			}
		}
	else
		{
		for ( data_id in r2 )
			{
			if ( data_id in r1 )
				result[data_id] = compose_resultvals(r1[data_id], r2[data_id]);
			else
				result[data_id] = r2[data_id];
			}
		}
	
	return result;
	}


function reset(ss: SumStat)
	{
	if ( ss$id in result_store )
		delete result_store[ss$id];

	result_store[ss$id] = table();

	if ( ss?$threshold || ss?$threshold_series )
		{
		threshold_tracker[ss$id] = table();
		event SumStats::thresholds_reset(ss$id);
		}
	}

function create(ss: SumStat)
	{
	if ( (ss?$threshold || ss?$threshold_series) && ! ss?$threshold_val )
		{
		Reporter::error("SumStats given a threshold with no $threshold_val function");
		}

	if ( ! ss?$id )
		ss$id=unique_id("");
	threshold_tracker[ss$id] = table();
	stats_store[ss$id] = ss;

	for ( reducer in ss$reducers )
		{
		reducer$sid = ss$id;
		if ( reducer$stream !in reducer_store )
			reducer_store[reducer$stream] = set();
		add reducer_store[reducer$stream][reducer];
		}

	reset(ss);
	schedule ss$epoch { SumStats::finish_epoch(ss) };
	}

function observe(id: string, key: Key, obs: Observation)
	{
	if ( id !in reducer_store )
		return;

	# Try to add the data to all of the defined reducers.
	for ( r in reducer_store[id] )
		{
		if ( r?$normalize_key )
			key = r$normalize_key(copy(key));

		# If this reducer has a predicate, run the predicate 
		# and skip this key if the predicate return false.
		if ( r?$pred && ! r$pred(key, obs) )
			next;
		
		local ss = stats_store[r$sid];
		
		# If there is a threshold and no epoch_finished callback
		# we don't need to continue counting since the data will
		# never be accessed.  This was leading
		# to some state management issues when measuring 
		# uniqueness.
		# NOTE: this optimization could need removed in the 
		#       future if on demand access is provided to the
		#       SumStats results.
		if ( ! ss?$epoch_finished &&
		     r$sid in threshold_tracker &&
		     key in threshold_tracker[r$sid] &&
		     ( ss?$threshold && 
		       threshold_tracker[r$sid][key]$is_threshold_crossed ) ||
		     ( ss?$threshold_series &&
		       threshold_tracker[r$sid][key]$threshold_series_index+1 == |ss$threshold_series| ) )
			next;

		if ( r$sid !in result_store )
			result_store[ss$id] = table();
		local results = result_store[r$sid];

		if ( key !in results )
			results[key] = table();
		local result = results[key];

		if ( id !in result )
			result[id] = init_resultval(r);
		local result_val = result[id];

		++result_val$num;
		# Continually update the $end field.
		result_val$end=network_time();

		# If a string was given, fall back to 1.0 as the value.
		local val = 1.0;
		if ( obs?$num || obs?$dbl )
			val = obs?$dbl ? obs$dbl : obs$num;

		hook observe_hook(r, val, obs, result_val);
		data_added(ss, key, result);
		}
	}

# This function checks if a threshold has been crossed.  It is also used as a method to implement 
# mid-break-interval threshold crossing detection for cluster deployments.
function check_thresholds(ss: SumStat, key: Key, result: Result, modify_pct: double): bool
	{
	if ( ! (ss?$threshold || ss?$threshold_series) )
		return F;

	# Add in the extra ResultVals to make threshold_vals easier to write.
	if ( |ss$reducers| != |result| )
		{
		for ( reducer in ss$reducers )
			{
			if ( reducer$stream !in result )
				result[reducer$stream] = init_resultval(reducer);
			}
		}

	local watch = ss$threshold_val(key, result);

	if ( modify_pct < 1.0 && modify_pct > 0.0 )
		watch = double_to_count(floor(watch/modify_pct));

	if ( ss$id !in threshold_tracker )
		threshold_tracker[ss$id] = table();
	local t_tracker = threshold_tracker[ss$id];

	if ( key !in t_tracker )
		{
		local ttmp: Thresholding;
		t_tracker[key] = ttmp;
		}
	local tt = t_tracker[key];

	if ( ss?$threshold && ! tt$is_threshold_crossed && watch >= ss$threshold )
		{
		# Value crossed the threshold.
		return T;
		}

	if ( ss?$threshold_series &&
	     |ss$threshold_series| >= tt$threshold_series_index &&
	     watch >= ss$threshold_series[tt$threshold_series_index] )
		{
		# A threshold series was given and the value crossed the next 
		# value in the series.
		return T;
		}

	return F;
	}

function threshold_crossed(ss: SumStat, key: Key, result: Result)
	{
	# If there is no callback, there is no point in any of this.
	if ( ! ss?$threshold_crossed )
		return;

	# Add in the extra ResultVals to make threshold_crossed callbacks easier to write.
	if ( |ss$reducers| != |result| )
		{
		for ( reducer in ss$reducers )
			{
			if ( reducer$stream !in result )
				result[reducer$stream] = init_resultval(reducer);
			}
		}

	ss$threshold_crossed(key, result);
	local tt = threshold_tracker[ss$id][key];
	tt$is_threshold_crossed = T;

	# Bump up to the next threshold series index if a threshold series is being used.
	if ( ss?$threshold_series )
		++tt$threshold_series_index;
	}

