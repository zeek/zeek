##! The metrics framework provides a way to count and measure data.  

@load base/utils/queue

module Measurement;

export {
	## The metrics logging stream identifier.
	redef enum Log::ID += { LOG };
	
	## This is the interval for how often threshold based notices will happen 
	## after they have already fired.
	const threshold_crossed_restart_interval = 1hr &redef;
	
	## The various calculations are all defined as plugins.
	type Calculation: enum {
		PLACEHOLDER
	};

	## Represents a thing which is having metrics collected for it.  An instance
	## of this record type and an id together represent a single measurement.
	type Index: record {
		## A non-address related metric or a sub-key for an address based metric.
		## An example might be successful SSH connections by client IP address
		## where the client string would be the index value.
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

	## Value supplied when a metric is finished.  It contains all
	## of the measurements collected for the metric.  Most of the
	## fields are added by calculation plugins.
	type ResultVal: record {
		## The time when this result was first started.
		begin:    time          &log;

		## The time when the last value was added to this result.
		end:      time          &log;

		## The number of measurements received.
		num:      count         &log &default=0;

		## A sample of something being measured.  This is helpful in 
		## some cases for collecting information to do further detection
		## or better logging for forensic purposes.
		samples:  vector of string   &optional;
	};
	
	type Measurement: record {
		## The calculations to perform on the data.
		apply:          set[Calculation];
		
		## A predicate so that you can decide per index if you would like
		## to accept the data being inserted.
		pred:           function(index: Measurement::Index, data: Measurement::DataPoint): bool &optional;
		
		## A function to normalize the index.  This can be used to aggregate or
		## normalize the entire index.
		normalize_func: function(index: Measurement::Index): Index &optional;

		## A number of sample DataPoints to collect.
		samples:        count &optional;
	};


	type Results: record {
		begin: time;
		end:   time;
		result
	};

	## Type to store a table of metrics result values.
	type ResultTable: table[Index] of Results;

	## Filters define how the data from a metric is aggregated and handled.  
	## Filters can be used to set how often the measurements are cut 
	## and logged or how the data within them is aggregated.
	type Filter: record {
		## A name for the filter in case multiple filters are being
		## applied to the same metric.  In most cases the default 
		## filter name is fine and this field does not need to be set.
		id:              string;

		## The interval at which this filter should be "broken" and written
		## to the logging stream.  The counters are also reset to zero at 
		## this time so any threshold based detection needs to be set to a 
		## number that should be expected to happen within this period.
		every:              interval;

		## Optionally provide a function to calculate a value from the ResultVal 
		## structure which will be used for thresholding.  If no function is 
		## provided, then in the following order of preference either the 
		## $unique or the $sum fields will be used.
		threshold_val_func: function(val: Measurement::ResultVal): count  &optional;

		## The threshold value for calling the $threshold_crossed callback.
		threshold:          count                    &optional;
		
		## A series of thresholds for calling the $threshold_crossed callback.
		threshold_series:   vector of count          &optional;
		
		## A callback with the full collection of ResultVals for this filter.
		## It's best to not access any global state outside of the variables
		## given to the callback because there is no assurance provided as to
		## where the callback will be executed on clusters.
		period_finished:    function(data: Measurement::ResultTable) &optional;

		## A callback that is called when a threshold is crossed.
		threshold_crossed:  function(index: Measurement::Index, val: Measurement::ResultVal) &optional;
	};
	
	## Function to associate a metric filter with a metric ID.
	## 
	## id: The metric ID that the filter should be associated with.
	##
	## filter: The record representing the filter configuration.
	global add_filter: function(id: string, filter: Measurement::Filter);
	
	## Add data into a metric.  This should be called when
	## a script has measured some point value and is ready to increment the
	## counters.
	##
	## id: The metric identifier that the data represents.
	##
	## index: The metric index that the value is to be added to.
	##
	## increment: How much to increment the counter by.
	global add_data: function(id: string, index: Measurement::Index, data: Measurement::DataPoint);

	## Helper function to represent a :bro:type:`Measurement::Index` value as 
	## a simple string.
	## 
	## index: The metric index that is to be converted into a string.
	##
	## Returns: A string reprentation of the metric index.
	global index2str: function(index: Measurement::Index): string;
	
	## Event to access metrics records as they are passed to the logging framework.
	global log_metrics: event(rec: Measurement::Info);
	
}

redef record Filter += {
	# Internal use only.  The metric that this filter applies to.  The value is automatically set.
	id: string &optional;
};

redef record ResultVal += {
	# Internal use only.  This is the queue where samples
	# are maintained since the queue is self managing for
	# the number of samples requested.
	sample_queue: Queue::Queue &optional;

	# Internal use only.  Indicates if a simple threshold was already crossed.
	is_threshold_crossed: bool &default=F;

	# Internal use only.  Current index for threshold series.
	threshold_series_index: count &default=0;
};

# Store the filters indexed on the metric identifier and filter name.
global filter_store: table[string, string] of Filter = table();

# This is indexed by metric id and filter name.
global store: table[string, string] of ResultTable = table();

# This is a hook for watching thresholds being crossed.  It is called whenever
# index values are updated and the new val is given as the `val` argument.
# It's only prototyped here because cluster and non-cluster have separate 
# implementations.
global data_added: function(filter: Filter, index: Index, val: ResultVal);

# Prototype the hook point for plugins to do calculations.
global add_to_calculation: hook(filter: Filter, val: double, data: DataPoint, result: ResultVal);
# Prototype the hook point for plugins to merge Measurements.
global plugin_merge_measurements: hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal);

# Event that is used to "finish" metrics and adapt the metrics
# framework for clustered or non-clustered usage.
global finish_period: event(filter: Measurement::Filter);

event bro_init() &priority=5
	{
	Log::create_stream(Measurement::LOG, [$columns=Info, $ev=log_metrics]);
	}

function index2str(index: Index): string
	{
	local out = "";
	if ( index?$host )
		out = fmt("%shost=%s", out, index$host);
	if ( index?$str )
		out = fmt("%s%sstr=%s", out, |out|==0 ? "" : ", ", index$str);
	return fmt("metric_index(%s)", out);
	}

function merge_result_vals(rv1: ResultVal, rv2: ResultVal): ResultVal
	{
	local result: ResultVal;

	# Merge $begin (take the earliest one)
	result$begin = (rv1$begin < rv2$begin) ? rv1$begin : rv2$begin;

	# Merge $end (take the latest one)
	result$end = (rv1$end > rv2$end) ? rv1$end : rv2$end;

	# Merge $num
	result$num = rv1$num + rv2$num;

	hook plugin_merge_measurements(result, rv1, rv2);
	
	# Merge $sample_queue
	if ( rv1?$sample_queue && rv2?$sample_queue )
		result$sample_queue = Queue::merge(rv1$sample_queue, rv2$sample_queue);
	else if ( rv1?$sample_queue )
		result$sample_queue = rv1$sample_queue;
	else if ( rv2?$sample_queue )
		result$sample_queue = rv2$sample_queue;
	
	# Merge $threshold_series_index
	result$threshold_series_index = (rv1$threshold_series_index > rv2$threshold_series_index) ? rv1$threshold_series_index : rv2$threshold_series_index;

	# Merge $is_threshold_crossed
	if ( rv1$is_threshold_crossed || rv2$is_threshold_crossed )
		result$is_threshold_crossed = T;

	return result;
	}
	
function reset(filter: Filter)
	{
	if ( [filter$id, filter$name] in store )
		delete store[filter$id, filter$name];

	store[filter$id, filter$name] = table();
	}

function add_filter(id: string, filter: Filter)
	{
	if ( [id, filter$name] in store )
		{
		Reporter::warning(fmt("invalid Metric filter (%s): Filter with same name already exists.", filter$name));
		return;
		}

	if ( ! filter?$id )
		filter$id = id;
	
	filter_store[id, filter$name] = filter;
	store[id, filter$name] = table();

	schedule filter$every { Measurement::finish_period(filter) };
	}

function add_data(id: string, index: Index, data: DataPoint)
	{
	# Try to add the data to all of the defined filters for the metric.
	for ( [metric_id, filter_id] in filter_store )
		{
		local filter = filter_store[metric_id, filter_id];
		
		# If this filter has a predicate, run the predicate and skip this
		# index if the predicate return false.
		if ( filter?$pred && ! filter$pred(index, data) )
			next;
		
		#if ( filter?$normalize_func )
		#	index = filter$normalize_func(copy(index));
		
		local metric_tbl = store[id, filter$name];
		if ( index !in metric_tbl )
			metric_tbl[index] = [$begin=network_time(), $end=network_time()];

		local result = metric_tbl[index];

		# If a string was given, fall back to 1.0 as the value.
		local val = 1.0;
		if ( data?$num || data?$dbl )
			val = data?$dbl ? data$dbl : data$num;

		++result$num;
		# Continually update the $end field.
		result$end=network_time();

		#if ( filter?$samples && filter$samples > 0 && data?$str )
		#	{
		#	if ( ! result?$sample_queue )
		#		result$sample_queue = Queue::init([$max_len=filter$samples]);
		#	Queue::push(result$sample_queue, data$str);
		#	}

		hook add_to_calculation(filter, val, data, result);
		data_added(filter, index, result);
		}
	}

# This function checks if a threshold has been crossed.  It is also used as a method to implement 
# mid-break-interval threshold crossing detection for cluster deployments.
function check_thresholds(filter: Filter, index: Index, val: ResultVal, modify_pct: double): bool
	{
	if ( ! (filter?$threshold || filter?$threshold_series) )
		return;

	local watch = 0.0;
	if ( val?$unique )
		watch = val$unique;
	else if ( val?$sum )
		watch = val$sum;

	if ( filter?$threshold_val_func )
		watch = filter$threshold_val_func(val);

	if ( modify_pct < 1.0 && modify_pct > 0.0 )
		watch = watch/modify_pct;

	if ( ! val$is_threshold_crossed &&
	     filter?$threshold && watch >= filter$threshold )
		{
		# A default threshold was given and the value crossed it.
		return T;
		}

	if ( filter?$threshold_series &&
	     |filter$threshold_series| >= val$threshold_series_index &&
	     watch >= filter$threshold_series[val$threshold_series_index] )
		{
		# A threshold series was given and the value crossed the next 
		# value in the series.
		return T;
		}

	return F;
	}

function threshold_crossed(filter: Filter, index: Index, val: ResultVal)
	{
	if ( ! filter?$threshold_crossed )
		return;

	if ( val?$sample_queue )
		val$samples = Queue::get_str_vector(val$sample_queue);

	filter$threshold_crossed(index, val);
	val$is_threshold_crossed = T;

	# Bump up to the next threshold series index if a threshold series is being used.
	if ( filter?$threshold_series )
		++val$threshold_series_index;
	}

