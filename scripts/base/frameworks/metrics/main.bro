##! The metrics framework provides a way to count and measure data.  

@load base/utils/queue

module Metrics;

export {
	## The metrics logging stream identifier.
	redef enum Log::ID += { LOG };
	
	## The default interval used for "breaking" metrics and writing the 
	## current value to the logging stream.
	const default_break_interval = 15mins &redef;
	
	## This is the interval for how often threshold based notices will happen 
	## after they have already fired.
	const threshold_crossed_restart_interval = 1hr &redef;
	
	type Calculation: enum {
		## Sums the values given.  For string values,
		## this will be the number of strings given.
		SUM,
		## Find the minimum value.
		MIN,
		## Find the maximum value.
		MAX,
		## Find the variance of the values.
		VARIANCE,
		## Find the standard deviation of the values.
		STD_DEV,
		## Calculate the average of the values.
		AVG,
		## Calculate the number of unique values.
		UNIQUE,
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
		
		## The CIDR block that this metric applies to.  This is typically
		## only used internally for host based aggregation.
		network:      subnet &optional;
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
	## of the measurements collected for the metric.
	type ResultVal: record {
		## The number of measurements received.
		num:      count         &log &default=0;

		## For numeric data, this tracks the sum of all values.
		sum:      double        &log &optional;

		## For numeric data, this tracks the minimum value given.
		min:      double        &log &optional;

		## For numeric data, this tracks the maximum value given.
		max:      double        &log &optional;

		## For numeric data, this calculates the average of all values.
		avg:      double        &log &optional;

		## For numeric data, this calculates the variance.
		variance: double        &log &optional;

		## For numeric data, this calculates the standard deviation.
		std_dev:  double        &log &optional;

		## If cardinality is being tracked, the number of unique
		## items is tracked here.
		unique:   count         &log &optional;

		## A sample of something being measured.  This is helpful in 
		## some cases for collecting information to do further detection
		## or better logging for forensic purposes.
		samples:  vector of string   &optional;
	};

	## The record type that is used for logging metrics.
	type Info: record {
		## Timestamp at which the metric was "broken".
		ts:           time     &log;
		## Interval between logging of this filter and the last time it was logged.
		ts_delta:     interval &log;
		## The name of the filter being logged.  Values
		## can have multiple filters which represent different perspectives on
		## the data so this is necessary to understand the value.
		filter_name:  string   &log;
		## What measurement the metric represents.
		metric:       string   &log;
		## What the metric value applies to.
		index:        Index    &log;
		## The simple numeric value of the metric.
		result:        ResultVal    &log;
	};
	
	## Filters define how the data from a metric is aggregated and handled.  
	## Filters can be used to set how often the measurements are cut 
	## and logged or how the data within them is aggregated.  It's also 
	## possible to disable logging and use filters solely for thresholding.
	type Filter: record {
		## The name for this filter so that multiple filters can be
		## applied to a single metrics to get a different view of the same
		## metric data being collected (different aggregation, break, etc).
		name:              string                   &default="default";
		## The metric that this filter applies to.
		id:                string                   &optional;
		## The measurements to perform on the data.
		measure:           set[Calculation]         &optional;
		## A predicate so that you can decide per index if you would like
		## to accept the data being inserted.
		pred:              function(index: Metrics::Index, data: DataPoint): bool &optional;
		## A function to normalize the index.  This can be used to aggregate or
		## normalize the entire index.
		normalize_func:    function(index: Metrics::Index): Index &optional;
		## Global mask by to aggregate traffic measuring an attribute of hosts.
		## This is a special case of the normalize_func.
		aggregation_mask:  count                    &optional;
		## The interval at which this filter should be "broken" and written
		## to the logging stream.  The counters are also reset to zero at 
		## this time so any threshold based detection needs to be set to a 
		## number that should be expected to happen within this period.
		every:             interval                 &default=default_break_interval;
		## This determines if the result of this filter is sent to the metrics
		## logging stream.  One use for the logging framework is as an internal
		## thresholding and statistics gathering utility that is meant to
		## never log but rather to generate notices and derive data.
		log:               bool                     &default=T;
		## A direct threshold for calling the $threshold_crossed function when 
		## the SUM is greater than or equal to this value.
		threshold:         count                    &optional;
		## A series of thresholds for calling the $threshold_crossed function.
		threshold_series:  vector of count          &optional;
		## A predicate so that you can decide when to flexibly declare when 
		## a threshold crossed, and do extra work.
		threshold_func:    function(index: Metrics::Index, val: Metrics::ResultVal): bool &optional;
		## A function callback that is called when a threshold is crossed.
		threshold_crossed: function(index: Metrics::Index, val: Metrics::ResultVal) &optional;
		## A number of sample DataPoint strings to collect for the threshold 
		## crossing callback.
		samples:           count                    &optional;
	};
	
	## Function to associate a metric filter with a metric ID.
	## 
	## id: The metric ID that the filter should be associated with.
	##
	## filter: The record representing the filter configuration.
	global add_filter: function(id: string, filter: Metrics::Filter);
	
	## Add data into a metric.  This should be called when
	## a script has measured some point value and is ready to increment the
	## counters.
	##
	## id: The metric identifier that the data represents.
	##
	## index: The metric index that the value is to be added to.
	##
	## increment: How much to increment the counter by.
	global add_data: function(id: string, index: Metrics::Index, data: Metrics::DataPoint);
	
	## Helper function to represent a :bro:type:`Metrics::Index` value as 
	## a simple string.
	## 
	## index: The metric index that is to be converted into a string.
	##
	## Returns: A string reprentation of the metric index.
	global index2str: function(index: Metrics::Index): string;
		
	## Event to access metrics records as they are passed to the logging framework.
	global log_metrics: event(rec: Metrics::Info);
	
}

redef record ResultVal += {
	# Internal use only.  Used for incrementally calculating variance.
	prev_avg:      double      &optional;

	# Internal use only.  For calculating variance.
	var_s:         double      &optional;

	# Internal use only.  This is not meant to be publically available 
	# because we don't want to trust that we can inspect the values 
	# since we will like move to a probalistic data structure in the future.
	# TODO: in the future this will optionally be a hyperloglog structure
	unique_vals:  set[DataPoint] &optional;

	# Internal use only.  This is the queue where samples
	# are maintained since the queue is self managing for
	# the number of samples requested.
	sample_queue: Queue::Queue &optional;

	# Internal use only.  Indicates if a simple threshold was already crossed.
	is_threshold_crossed: bool &default=F;

	# Internal use only.  Current index for threshold series.
	threshold_series_index: count &default=0;
};

# Type to store a table of metrics values.
type MetricTable: table[Index] of ResultVal;

# Store the filters indexed on the metric identifier.
global metric_filters: table[string] of vector of Filter = table();

# Store the filters indexed on the metric identifier and filter name.
global filter_store: table[string, string] of Filter = table();

# This is indexed by metric id and filter name.
global store: table[string, string] of MetricTable = table() &default=table();

# This is hook for watching thresholds being crossed.  It is called whenever
# index values are updated and the new val is given as the `val` argument.
# It's only prototyped here because cluster and non-cluster has separate 
# implementations.
global data_added: function(filter: Filter, index: Index, val: ResultVal);

## Event that is used to "finish" metrics and adapt the metrics
## framework for clustered or non-clustered usage.
global log_it: event(filter: Metrics::Filter);


event bro_init() &priority=5
	{
	Log::create_stream(Metrics::LOG, [$columns=Info, $ev=log_metrics]);
	}

function index2str(index: Index): string
	{
	local out = "";
	if ( index?$host )
		out = fmt("%shost=%s", out, index$host);
	if ( index?$network )
		out = fmt("%s%snetwork=%s", out, |out|==0 ? "" : ", ", index$network);
	if ( index?$str )
		out = fmt("%s%sstr=%s", out, |out|==0 ? "" : ", ", index$str);
	return fmt("metric_index(%s)", out);
	}
	
function do_calculated_fields(val: ResultVal)
	{
	if ( val?$unique_vals )
		val$unique = |val$unique_vals|;
	if ( val?$var_s )
		val$variance = (val$num > 1) ? val$var_s/val$num : 0.0;
	if ( val?$variance )
		val$std_dev = sqrt(val$variance);
	}

function merge_result_vals(rv1: ResultVal, rv2: ResultVal): ResultVal
	{
	local result: ResultVal;
	
	# Merge $num
	result$num = rv1$num + rv2$num;

	# Merge $sum
	if ( rv1?$sum || rv2?$sum )
		{
		result$sum = 0;
		if ( rv1?$sum )
			result$sum += rv1$sum;
		if ( rv2?$sum )
			result$sum += rv2$sum;
		}
	
	# Merge $max
	if ( rv1?$max && rv2?$max )
		result$max = (rv1$max > rv2$max) ? rv1$max : rv2$max;
	else if ( rv1?$max )
		result$max = rv1$max;
	else if ( rv2?$max )
		result$max = rv2$max;

	# Merge $min
	if ( rv1?$min && rv2?$min )
		result$min = (rv1$min < rv2$min) ? rv1$min : rv2$min;
	else if ( rv1?$min )
		result$min = rv1$min;
	else if ( rv2?$min )
		result$min = rv2$min;

	# Merge $avg
	if ( rv1?$avg && rv2?$avg )
		result$avg = ((rv1$avg*rv1$num) + (rv2$avg*rv2$num))/(rv1$num+rv2$num);
	else if ( rv1?$avg )
		result$avg = rv1$avg;
	else if ( rv2?$avg )
		result$avg = rv2$avg;

	# Merge $prev_avg
	if ( rv1?$prev_avg && rv2?$prev_avg )
		result$prev_avg = ((rv1$prev_avg*rv1$num) + (rv2$prev_avg*rv2$num))/(rv1$num+rv2$num);
	else if ( rv1?$prev_avg )
		result$prev_avg = rv1$prev_avg;
	else if ( rv2?$prev_avg )
		result$prev_avg = rv2$prev_avg;

	# Merge $var_s
	if ( rv1?$var_s && rv2?$var_s )
		{
		local rv1_avg_sq = (rv1$avg - result$avg);
		rv1_avg_sq = rv1_avg_sq*rv1_avg_sq;
		local rv2_avg_sq = (rv2$avg - result$avg);
		rv2_avg_sq = rv2_avg_sq*rv2_avg_sq;
		result$var_s = rv1$num*(rv1$var_s/rv1$num + rv1_avg_sq) + rv2$num*(rv2$var_s/rv2$num + rv2_avg_sq);
		}
	else if ( rv1?$var_s )
		result$var_s = rv1$var_s;
	else if ( rv2?$var_s )
		result$var_s = rv2$var_s;

	# Merge $unique_vals
	if ( rv1?$unique_vals || rv2?$unique_vals )
		{
		result$unique_vals = set();
		if ( rv1?$unique_vals )
			for ( val1 in rv1$unique_vals )
				add result$unique_vals[val1];
		if ( rv2?$unique_vals )
			for ( val2 in rv2$unique_vals )
				add result$unique_vals[val2];
		}

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

	do_calculated_fields(result);
	return result;
	}
	
function write_log(ts: time, filter: Filter, data: MetricTable)
	{
	for ( index in data )
		{
		local m: Info = [$ts=ts,
		                 $ts_delta=filter$every,
		                 $metric=filter$id,
		                 $filter_name=filter$name,
		                 $index=index,
		                 $result=data[index]];
		
		if ( filter$log )
			Log::write(Metrics::LOG, m);
		}
	}

function reset(filter: Filter)
	{
	store[filter$id, filter$name] = table();
	}

function add_filter(id: string, filter: Filter)
	{
	if ( filter?$normalize_func && filter?$aggregation_mask )
		{
		Reporter::warning(fmt("invalid Metric filter (%s): Defined $normalize_func and $aggregation_mask.", filter$name));
		return;
		}
	if ( [id, filter$name] in store )
		{
		Reporter::warning(fmt("invalid Metric filter (%s): Filter with same name already exists.", filter$name));
		return;
		}
	
	if ( ! filter?$id )
		filter$id = id;
	
	if ( id !in metric_filters )
		metric_filters[id] = vector();
	metric_filters[id][|metric_filters[id]|] = filter;

	filter_store[id, filter$name] = filter;
	store[id, filter$name] = table();
	
	schedule filter$every { Metrics::log_it(filter) };
	}

function add_data(id: string, index: Index, data: DataPoint)
	{
	if ( id !in metric_filters )
		return;
	
	local filters = metric_filters[id];
	
	# Try to add the data to all of the defined filters for the metric.
	for ( filter_id in filters )
		{
		local filter = filters[filter_id];
		
		# If this filter has a predicate, run the predicate and skip this
		# index if the predicate return false.
		if ( filter?$pred && ! filter$pred(index, data) )
			next;
		
		if ( filter?$normalize_func )
			index = filter$normalize_func(copy(index));

		if ( index?$host && filter?$aggregation_mask )
			{
			index$network = mask_addr(index$host, filter$aggregation_mask);
			delete index$host;
			}
		
		local metric_tbl = store[id, filter$name];
		if ( index !in metric_tbl )
			metric_tbl[index] = [];

		local result = metric_tbl[index];

		# If a string was given, fall back to 1.0 as the value.
		local val = 1.0;
		if ( data?$num || data?$dbl )
			val = data?$dbl ? data$dbl : data$num;

		++result$num;

		if ( filter?$samples && data?$str )
			{
			if ( ! result?$sample_queue )
				result$sample_queue = Queue::init([$max_len=filter$samples]);
			Queue::push(result$sample_queue, data$str);
			}

		if ( SUM in filter$measure )
			{
			if ( ! result?$sum ) result$sum = 0;
			result$sum += val;
			}

		if ( MIN in filter$measure )
			{
			if ( ! result?$min ) 
				result$min = val;
			else if ( val < result$min )
				result$min = val;
			}

		if ( MAX in filter$measure )
			{
			if ( ! result?$max ) 
				result$max = val;
			else if ( val > result$max )
				result$max = val;
			}
	
		if ( AVG in filter$measure || VARIANCE in filter$measure )
			{
			if ( ! result?$avg ) 
				{
				result$avg = val;
				result$prev_avg = val;
				}
			else
				{
				result$prev_avg = result$avg;
				result$avg += (val - result$avg) / result$num;
				}
			}

		if ( VARIANCE in filter$measure )
			{
			if ( ! result?$var_s ) result$var_s = 0.0;
			result$var_s += (val - result$prev_avg)*(val - result$avg);
			}

		if ( STD_DEV in filter$measure )
			{
			#if ( result?$variance )
			#	result$std_dev = sqrt(result$variance);
			}

		if ( UNIQUE in filter$measure )
			{
			if ( ! result?$unique_vals ) result$unique_vals=set();
			add result$unique_vals[data];
			}

		do_calculated_fields(result);
		data_added(filter, index, result);
		}
	}

# This function checks if a threshold has been crossed and generates a 
# notice if it has.  It is also used as a method to implement 
# mid-break-interval threshold crossing detection for cluster deployments.
function check_thresholds(filter: Filter, index: Index, val: ResultVal, modify_pct: double): bool
	{
	local watch = 0.0;
	if ( val?$unique )
		watch = val$unique;
	else if ( val?$sum )
		watch = val$sum;

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

	if ( ! val$is_threshold_crossed &&
	     filter?$threshold_func &&
	     filter$threshold_func(index, val) )
		{
		# The threshold function indicated it was crossed.
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
