##! The measurement framework provides a way to count and measure data.  

module Measurement;

export {
	## The various calculations are all defined as plugins.
	type Calculation: enum {
		PLACEHOLDER
	};

	## Represents a thing which is having measurement results collected for it.
	type Key: record {
		## A non-address related measurement or a sub-key for an address based measurement.
		## An example might be successful SSH connections by client IP address
		## where the client string would be the key value.
		## Another example might be number of HTTP requests to a particular
		## value in a Host header.  This is an example of a non-host based
		## metric since multiple IP addresses could respond for the same Host
		## header value.
		str:  string &optional;
	
		## Host is the value to which this metric applies.
		host: addr &optional;
	};
	
	## Represents data being added for a single metric data point.
	## Only supply a single value here at a time.
	type DataPoint: record {
		## Count value.
		num:  count  &optional;
		## Double value.
		dbl:  double &optional;
		## String value.
		str:  string &optional;
	};

	type Reducer: record {
		## Data stream identifier for the reducer to attach to.
		stream:         string;

		## The calculations to perform on the data points.
		apply:          set[Calculation];
		
		## A predicate so that you can decide per key if you would like
		## to accept the data being inserted.
		pred:           function(key: Measurement::Key, point: Measurement::DataPoint): bool &optional;
		
		## A function to normalize the key.  This can be used to aggregate or
		## normalize the entire key.
		normalize_key:  function(key: Measurement::Key): Key &optional;
	};

	## Value calculated for a data point stream fed into a reducer.
	## Most of the fields are added by plugins.
	type ResultVal: record {
		## The time when the first data point was added to this result value.
		begin:  time;

		## The time when the last data point was added to this result value.
		end:    time;

		## The number of measurements received.
		num:    count &default=0;
	};

	## Type to store results for multiple reducers.
	type Result: table[string] of ResultVal;

	## Type to store a table of measurement results indexed by the measurement key.
	type ResultTable: table[Key] of Result;

	## Measurements represent an aggregation of reducers along with 
	## mechanisms to handle various situations like the epoch ending
	## or thresholds being crossed.
	type Measurement: record {
		## The interval at which this filter should be "broken" and the
		## '$epoch_finished' callback called.  The results are also reset 
		## at this time so any threshold based detection needs to be set to a 
		## number that should be expected to happen within this epoch.
		epoch:              interval;

		## The reducers for the measurement indexed by data id.
		reducers:           set[Reducer];

		## Provide a function to calculate a value from the :bro:see:`Result`
		## structure which will be used for thresholding.
		threshold_val:      function(key: Measurement::Key, result: Measurement::Result): count &optional;

		## The threshold value for calling the $threshold_crossed callback.
		threshold:          count             &optional;
		
		## A series of thresholds for calling the $threshold_crossed callback.
		threshold_series:   vector of count   &optional;

		## A callback that is called when a threshold is crossed.
		threshold_crossed:  function(key: Measurement::Key, result: Measurement::Result) &optional;
		
		## A callback with the full collection of Results for this filter.
		## It's best to not access any global state outside of the variables
		## given to the callback because there is no assurance provided as to
		## where the callback will be executed on clusters.
		epoch_finished:    function(rt: Measurement::ResultTable) &optional;
	};
	
	## Create a measurement.
	global create: function(m: Measurement::Measurement);

	## Add data into a data point stream.  This should be called when
	## a script has measured some point value.
	##
	## id: The stream identifier that the data point represents.
	##
	## key: The measurement key that the value is to be added to.
	##
	## point: The data point to send into the stream.
	global add_data: function(id: string, key: Measurement::Key, point: Measurement::DataPoint);

	## Helper function to represent a :bro:type:`Measurement::Key` value as 
	## a simple string.
	## 
	## key: The metric key that is to be converted into a string.
	##
	## Returns: A string representation of the metric key.
	global key2str: function(key: Measurement::Key): string;

	## This event is generated for each new measurement that is created.
	##
	## m: The record which describes a measurement.
	global new_measurement: event(m: Measurement);
}

redef record Reducer += {
	# Internal use only.  Provides a reference back to the related Measurement by it's ID.
	mid: string &optional;
};

type Thresholding: record {
	# Internal use only.  Indicates if a simple threshold was already crossed.
	is_threshold_crossed: bool &default=F;

	# Internal use only.  Current key for threshold series.
	threshold_series_index: count &default=0;
};

# Internal use only.  For tracking thresholds per measurement and key.
global threshold_tracker: table[string] of table[Key] of Thresholding &optional;

redef record Measurement += {
	# Internal use only (mostly for cluster coherency).
	id: string &optional;
};

# Store of measurements indexed on the measurement id.
global measurement_store: table[string] of Measurement = table();

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
global data_added: function(m: Measurement, key: Key, result: Result);

# Prototype the hook point for plugins to do calculations.
global add_to_reducer_hook: hook(r: Reducer, val: double, data: DataPoint, rv: ResultVal);
# Prototype the hook point for plugins to initialize any result values.
global init_resultval_hook: hook(r: Reducer, rv: ResultVal);
# Prototype the hook point for plugins to merge Results.
global compose_resultvals_hook: hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal);

# Event that is used to "finish" measurements and adapt the measurement
# framework for clustered or non-clustered usage.
global finish_epoch: event(m: Measurement);

function key2str(key: Key): string
	{
	local out = "";
	if ( key?$host )
		out = fmt("%shost=%s", out, key$host);
	if ( key?$str )
		out = fmt("%s%sstr=%s", out, |out|==0 ? "" : ", ", key$str);
	return fmt("measurement_key(%s)", out);
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

	# Merge $begin (take the earliest one)
	result$begin = (rv1$begin < rv2$begin) ? rv1$begin : rv2$begin;

	# Merge $end (take the latest one)
	result$end = (rv1$end > rv2$end) ? rv1$end : rv2$end;

	# Merge $num
	result$num = rv1$num + rv2$num;

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


function reset(m: Measurement)
	{
	if ( m$id in result_store )
		delete result_store[m$id];

	result_store[m$id] = table();
	threshold_tracker[m$id] = table();
	}

function create(m: Measurement)
	{
	if ( (m?$threshold || m?$threshold_series) && ! m?$threshold_val )
		{
		Reporter::error("Measurement given a threshold with no $threshold_val function");
		}

	if ( ! m?$id )
		m$id=unique_id("");
	threshold_tracker[m$id] = table();
	measurement_store[m$id] = m;

	for ( reducer in m$reducers )
		{
		reducer$mid = m$id;
		if ( reducer$stream !in reducer_store )
			reducer_store[reducer$stream] = set();
		add reducer_store[reducer$stream][reducer];
		}

	reset(m);
	schedule m$epoch { Measurement::finish_epoch(m) };
	}

function add_data(id: string, key: Key, point: DataPoint)
	{
	# Try to add the data to all of the defined reducers.
	if ( id !in reducer_store )
		return;

	for ( r in reducer_store[id] )
		{
		# If this reducer has a predicate, run the predicate 
		# and skip this key if the predicate return false.
		if ( r?$pred && ! r$pred(key, point) )
			next;
		
		if ( r?$normalize_key )
			key = r$normalize_key(copy(key));
		
		local m = measurement_store[r$mid];
		
		if ( r$mid !in result_store )
			result_store[m$id] = table();
		local results = result_store[r$mid];

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
		if ( point?$num || point?$dbl )
			val = point?$dbl ? point$dbl : point$num;

		hook add_to_reducer_hook(r, val, point, result_val);
		data_added(m, key, result);
		}
	}

# This function checks if a threshold has been crossed.  It is also used as a method to implement 
# mid-break-interval threshold crossing detection for cluster deployments.
function check_thresholds(m: Measurement, key: Key, result: Result, modify_pct: double): bool
	{
	if ( ! (m?$threshold || m?$threshold_series) )
		return F;

	# Add in the extra ResultVals to make threshold_vals easier to write.
	if ( |m$reducers| != |result| )
		{
		for ( reducer in m$reducers )
			{
			if ( reducer$stream !in result )
				result[reducer$stream] = init_resultval(reducer);
			}
		}

	local watch = m$threshold_val(key, result);

	if ( modify_pct < 1.0 && modify_pct > 0.0 )
		watch = double_to_count(floor(watch/modify_pct));

	if ( m$id !in threshold_tracker )
		threshold_tracker[m$id] = table();
	local t_tracker = threshold_tracker[m$id];

	if ( key !in t_tracker )
		{
		local ttmp: Thresholding;
		t_tracker[key] = ttmp;
		}
	local tt = threshold_tracker[m$id][key];

	if ( m?$threshold && ! tt$is_threshold_crossed && watch >= m$threshold )
		{
		# Value crossed the threshold.
		return T;
		}

	if ( m?$threshold_series &&
	     |m$threshold_series| >= tt$threshold_series_index &&
	     watch >= m$threshold_series[tt$threshold_series_index] )
		{
		# A threshold series was given and the value crossed the next 
		# value in the series.
		return T;
		}

	return F;
	}

function threshold_crossed(m: Measurement, key: Key, result: Result)
	{
	# If there is no callback, there is no point in any of this.
	if ( ! m?$threshold_crossed )
		return;

	# Add in the extra ResultVals to make threshold_crossed callbacks easier to write.
	if ( |m$reducers| != |result| )
		{
		for ( reducer in m$reducers )
			{
			if ( reducer$stream !in result )
				result[reducer$stream] = init_resultval(reducer);
			}
		}

	m$threshold_crossed(key, result);
	local tt = threshold_tracker[m$id][key];
	tt$is_threshold_crossed = T;

	# Bump up to the next threshold series index if a threshold series is being used.
	if ( m?$threshold_series )
		++tt$threshold_series_index;
	}

