##! The metrics framework provides a way to count and measure data.  

@load base/utils/queue

module Measurement;

export {
	## The various calculations are all defined as plugins.
	type Calculation: enum {
		PLACEHOLDER
	};

	## Represents a thing which is having measurement results collected for it.
	type Key: record {
		## A non-address related metric or a sub-key for an address based metric.
		## An example might be successful SSH connections by client IP address
		## where the client string would be the key value.
		## Another example might be number of HTTP requests to a particular
		## value in a Host header.  This is an example of a non-host based
		## metric since multiple IP addresses could respond for the same Host
		## header value.
		str:          string &optional;
	
		## Host is the value to which this metric applies.
		host:         addr &optional;
	} &log;
	
	## Represents data being added for a single metric data point.
	## Only supply a single value here at a time.
	type DataPoint: record {
		## Count value.
		num:       count       &optional;
		## Double value.
		dbl:       double      &optional;
		## String value.
		str:       string      &optional;
	};

	type Reducer: record {
		## Data stream identifier for the reducer to attach to.
		stream:         string;

		## The calculations to perform on the data points.
		apply:          set[Calculation];
		
		## A predicate so that you can decide per key if you would like
		## to accept the data being inserted.
		pred:           function(key: Measurement::Key, data: Measurement::DataPoint): bool &optional;
		
		## A function to normalize the key.  This can be used to aggregate or
		## normalize the entire key.
		normalize_key:  function(key: Measurement::Key): Key &optional;
	};

	## Value calculated for a data point stream fed into a reducer.
	## Most of the fields are added by plugins.
	type Result: record {
		## The time when the first data point was added to this result value.
		begin:    time          &log;

		## The time when the last data point was added to this result value.
		end:      time          &log;

		## The number of measurements received.
		num:      count         &log &default=0;
	};

	## Type to store a table of measurement results.  First table is
	## indexed on the measurement Key and the enclosed table is 
	## indexed on the data id that the Key was relevant for.
	type ResultTable: table[Key] of table[string] of Result;

	## Filters define how the data from a metric is aggregated and handled.  
	## Filters can be used to set how often the measurements are cut 
	## and logged or how the data within them is aggregated.
	type Measurement: record {
		## The interval at which this filter should be "broken" and the
		## callback called.  The counters are also reset to zero at 
		## this time so any threshold based detection needs to be set to a 
		## number that should be expected to happen within this period.
		epoch:              interval;

		## The reducers for the measurement indexed by data id.
		reducers:           set[Reducer];

		## Optionally provide a function to calculate a value from the Result 
		## structure which will be used for thresholding.
		threshold_val:      function(result: Measurement::Result): count  &optional;

		## The threshold value for calling the $threshold_crossed callback.
		threshold:          count                    &optional;
		
		## A series of thresholds for calling the $threshold_crossed callback.
		threshold_series:   vector of count          &optional;

		## A callback that is called when a threshold is crossed.
		threshold_crossed:  function(key: Measurement::Key, result: Measurement::Result) &optional;
		
		## A callback with the full collection of Results for this filter.
		## It's best to not access any global state outside of the variables
		## given to the callback because there is no assurance provided as to
		## where the callback will be executed on clusters.
		period_finished:    function(data: Measurement::ResultTable) &optional;
	};
	
	## Create a measurement.
	global create: function(m: Measurement::Measurement);

	## Add data into a metric.  This should be called when
	## a script has measured some point value and is ready to increment the
	## counters.
	##
	## id: The metric identifier that the data represents.
	##
	## key: The metric key that the value is to be added to.
	##
	## data: The data point to send into the stream.
	global add_data: function(id: string, key: Measurement::Key, data: Measurement::DataPoint);

	## Helper function to represent a :bro:type:`Measurement::Key` value as 
	## a simple string.
	## 
	## key: The metric key that is to be converted into a string.
	##
	## Returns: A string representation of the metric key.
	global key2str: function(key: Measurement::Key): string;
	
}

redef record Reducer += {
	# Internal use only.  Measurement ID.
	mid: string &optional;
};

redef record Result += {
	# Internal use only.  Indicates if a simple threshold was already crossed.
	is_threshold_crossed: bool &default=F;

	# Internal use only.  Current key for threshold series.
	threshold_series_index: count &default=0;
};

redef record Measurement += {
	# Internal use only (mostly for cluster coherency).
	id: string &optional;
};

# Store of reducers indexed on the data id.
global reducer_store: table[string] of set[Reducer] = table();

# Store of results indexed on the measurement id.
global result_store: table[string] of ResultTable = table();

# Store of measurements indexed on the measurement id.
global measurement_store: table[string] of Measurement = table();

# This is called whenever
# key values are updated and the new val is given as the `val` argument.
# It's only prototyped here because cluster and non-cluster have separate 
# implementations.
global data_added: function(m: Measurement, key: Key, result: Result);

# Prototype the hook point for plugins to do calculations.
global add_to_reducer: hook(r: Reducer, val: double, data: DataPoint, result: Result);
# Prototype the hook point for plugins to merge Results.
global compose_resultvals_hook: hook(result: Result, rv1: Result, rv2: Result);

# Event that is used to "finish" measurements and adapt the measurement
# framework for clustered or non-clustered usage.
global finish_period: event(m: Measurement);

function key2str(key: Key): string
	{
	local out = "";
	if ( key?$host )
		out = fmt("%shost=%s", out, key$host);
	if ( key?$str )
		out = fmt("%s%sstr=%s", out, |out|==0 ? "" : ", ", key$str);
	return fmt("metric_key(%s)", out);
	}

function compose_resultvals(rv1: Result, rv2: Result): Result
	{
	local result: Result;

	# Merge $begin (take the earliest one)
	result$begin = (rv1$begin < rv2$begin) ? rv1$begin : rv2$begin;

	# Merge $end (take the latest one)
	result$end = (rv1$end > rv2$end) ? rv1$end : rv2$end;

	# Merge $num
	result$num = rv1$num + rv2$num;

	# Merge $threshold_series_index
	result$threshold_series_index = (rv1$threshold_series_index > rv2$threshold_series_index) ? rv1$threshold_series_index : rv2$threshold_series_index;

	# Merge $is_threshold_crossed
	if ( rv1$is_threshold_crossed || rv2$is_threshold_crossed )
		result$is_threshold_crossed = T;

	hook compose_resultvals_hook(result, rv1, rv2);

	return result;
	}
	
function reset(m: Measurement)
	{
	if ( m$id in result_store )
		delete result_store[m$id];

	result_store[m$id] = table();
	}

function create(m: Measurement)
	{
	m$id=unique_id("");
	measurement_store[m$id] = m;

	for ( reducer in m$reducers )
		{
		reducer$mid = m$id;
		if ( reducer$stream !in reducer_store )
			reducer_store[reducer$stream] = set();
		add reducer_store[reducer$stream][reducer];
		}

	reset(m);
	schedule m$epoch { Measurement::finish_period(m) };
	}

function add_data(data_id: string, key: Key, data: DataPoint)
	{
	# Try to add the data to all of the defined reducers.
	if ( data_id !in reducer_store )
		return;

	for ( r in reducer_store[data_id] )
		{
		# If this reducer has a predicate, run the predicate 
		# and skip this key if the predicate return false.
		if ( r?$pred && ! r$pred(key, data) )
			next;
		
		if ( r?$normalize_key )
			key = r$normalize_key(copy(key));
		
		local m = measurement_store[r$mid];
		local results = result_store[m$id];
		if ( key !in results )
			results[key] = table();
		if ( data_id !in results[key] )
			results[key][data_id] = [$begin=network_time(), $end=network_time()];

		local result = results[key][data_id];
		++result$num;
		# Continually update the $end field.
		result$end=network_time();

		# If a string was given, fall back to 1.0 as the value.
		local val = 1.0;
		if ( data?$num || data?$dbl )
			val = data?$dbl ? data$dbl : data$num;

		hook add_to_reducer(r, val, data, result);
		data_added(m, key, result);
		}
	}

# This function checks if a threshold has been crossed.  It is also used as a method to implement 
# mid-break-interval threshold crossing detection for cluster deployments.
function check_thresholds(m: Measurement, key: Key, result: Result, modify_pct: double): bool
	{
	if ( ! (m?$threshold || m?$threshold_series) )
		return F;

	local watch = 0.0;
	#if ( val?$unique )
	#	watch = val$unique;
	#else if ( val?$sum )
	#	watch = val$sum;

	if ( m?$threshold_val )
		watch = m$threshold_val(result);

	if ( modify_pct < 1.0 && modify_pct > 0.0 )
		watch = watch/modify_pct;

	if ( ! result$is_threshold_crossed &&
	     m?$threshold && watch >= m$threshold )
		{
		# A default threshold was given and the value crossed it.
		return T;
		}

	if ( m?$threshold_series &&
	     |m$threshold_series| >= result$threshold_series_index &&
	     watch >= m$threshold_series[result$threshold_series_index] )
		{
		# A threshold series was given and the value crossed the next 
		# value in the series.
		return T;
		}

	return F;
	}

function threshold_crossed(m: Measurement, key: Key, result: Result)
	{
	if ( ! m?$threshold_crossed )
		return;

	#if ( val?$sample_queue )
	#	val$samples = Queue::get_str_vector(val$sample_queue);

	m$threshold_crossed(key, result);
	result$is_threshold_crossed = T;

	# Bump up to the next threshold series index if a threshold series is being used.
	if ( m?$threshold_series )
		++result$threshold_series_index;
	}

