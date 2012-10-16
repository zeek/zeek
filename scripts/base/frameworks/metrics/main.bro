##! The metrics framework provides a way to count and measure data.  

@load base/frameworks/notice

module Metrics;

export {
	## The metrics logging stream identifier.
	redef enum Log::ID += { LOG };
	
	## The default interval used for "breaking" metrics and writing the 
	## current value to the logging stream.
	const default_break_interval = 15mins &redef;

	## The default number of metric items which trigger 
	## filter$custom_check_threshold 
	const default_trigger_custom_check_threshold = 10 &redef;
	
	## This is the interval for how often threshold based notices will happen 
	## after they have already fired.
	const threshold_series_restart_interval = 1hr &redef;
	
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
	
	## Represents data being added for a single metric data point.  Used internally.
	type DataPoint: record {
		num:        count       &optional;
		unique_vals: set[string] &optional;
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
		metric_id:    string   &log;
		## What the metric value applies to.
		index:        Index    &log;
		## The simple numeric value of the metric.
		value:        count    &log;
	};
	
    # TODO: configure a metrics filter logging stream to log the current
	#       metrics configuration in case someone is looking through
	#       old logs and the configuration has changed since then.
	
	## Filters define how the data from a metric is aggregated and handled.  
	## Filters can be used to set how often the measurements are cut or "broken"
	## and logged or how the data within them is aggregated.  It's also 
	## possible to disable logging and use filters for thresholding.
	type Filter: record {
		## The name for this filter so that multiple filters can be
		## applied to a single metrics to get a different view of the same
		## metric data being collected (different aggregation, break, etc).
		name:              string                  &default="default";
		## The :bro:type:`Metrics::ID` that this filter applies to.
		id:                string                  &optional;
		## A predicate so that you can decide per index if you would like
		## to accept the data being inserted.
		pred:              function(index: Index): bool &optional;
		## A function to normalize the index.  This can be used to normalize
		## any field in the index and is likely most useful to normalize
		## the $str field.
		normalize_func:    function(index: Index): Index &optional;
		## Global mask by which you'd like to aggregate traffic.
		aggregation_mask:  count                   &optional;
		## This is essentially a mapping table between addresses and subnets.
		aggregation_table: table[subnet] of subnet &optional;
		## The interval at which this filter should be "broken" and written
		## to the logging stream.  The counters are also reset to zero at 
		## this time so any threshold based detection needs to be set to a 
		## number that should be expected to happen within this period.
		break_interval:    interval                &default=default_break_interval;
		## This determines if the result of this filter is sent to the metrics
		## logging stream.  One use for the logging framework is as an internal
		## thresholding and statistics gathering utility that is meant to
		## never log but rather to generate notices and derive data.
		log:               bool                    &default=T;
		## A straight threshold for generating a notice.
		default_threshold:  count                   &optional;
		## A predicate so that you can decide when to flexibly declare when 
		## a threshold crossed, and do extra stuff
		custom_check_threshold:     function(index: Index, default_thresh: count, 
						     val: count ): bool &optional;
		## Even if custom_check_threshold has been defined, we don't want 
		## to call it every time because of function call overhead.
		## Metrics::Filter$trigger_custom_check_threshold describes how often
		## custom_check_threshold will be called
		## e.g. call custom_check_threshold for every 10 items seen by the metrics fw
		trigger_custom_check_threshold: count   &default=default_trigger_custom_check_threshold;
		## A predicate that is called whenever a threshold is crossed
		## ToDo: Also have a parameter here that is a sample of the
		## observed trackable items 
		threshold_crossed:     function(index: Index, val: count );
		## A series of thresholds at which to generate notices.
		threshold_series: vector of count         &optional;
	};
	
	## Function to associate a metric filter with a metric ID.
	## 
	## id: The metric ID that the filter should be associated with.
	##
	## filter: The record representing the filter configuration.
	global add_filter: function(id: string, filter: Filter);
	
	## Add data into a :bro:type:`Metrics::ID`.  This should be called when
	## a script has measured some point value and is ready to increment the
	## counters.
	##
	## id: The metric ID that the data represents.
	##
	## index: The metric index that the value is to be added to.
	##
	## increment: How much to increment the counter by.
	global add_data: function(id: string, index: Index, increment: count);

	# This function does the following:
	# If index (src,) doesn't exist, it creates an entry for this index. It
	# adds data (c$id$orig_h) to a set associated with this index. If the number
	# of unique data values for an index exceeds threshold, a notice is generated.
	# So the threshold applies to the number of unique data values associated with
	# an index.
	
	global add_unique: function(id: string, index: Index, data: string);
	
	## Helper function to represent a :bro:type:`Metrics::Index` value as 
	## a simple string
	## 
	## index: The metric index that is to be converted into a string.
	##
	## Returns: A string reprentation of the metric index.
	global index2str: function(index: Index): string;
	
	## Event that is used to "finish" metrics and adapt the metrics
	## framework for clustered or non-clustered usage.
	##
	## ..note: This is primarily intended for internal use.
	global log_it: event(filter: Filter);
	
	## Event to access metrics records as they are passed to the logging framework.
	global log_metrics: event(rec: Info);
	
	## Type to store a table of metrics values.  Interal use only!
	type MetricTable: table[Index] of DataPoint;
}

redef record Notice::Info += {
	metric_index: Index &log &optional;
};

global metric_filters: table[string] of vector of Filter = table();
global filter_store: table[string, string] of Filter = table();

# This is indexed by metric ID and stream filter name.
global store: table[string, string] of MetricTable = table() &default=table();

# This function checks if a threshold has been crossed and generates a 
# notice if it has.  It is also used as a method to implement 
# mid-break-interval threshold crossing detection for cluster deployments.
global check_threshold: function(filter: Filter, index: Index, val: count): bool;
# This is hook for watching thresholds being crossed.  It is called whenever
# index values are updated and the new val is given as the `val` argument.
global data_added: function(filter: Filter, index: Index, val: count);

# This stores the current threshold index for filters using $threshold_series.
global threshold_series_index: table[string, string, Index] of count = {} &create_expire=threshold_series_restart_interval &default=0;

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
	
function merge_data_points(dp1: DataPoint, dp2: DataPoint): DataPoint
	{
	local result: DataPoint;
	if ( dp1?$num || dp2?$num )
		{
		result$num = 0;
		if ( dp1?$num )
			result$num += dp1$num;
		if ( dp2?$num )
			result$num += dp2$num;
		}
		
	if ( dp1?$unique_vals || dp2?$unique_vals )
		{
		result$unique_vals = set();
		if ( dp1?$unique_vals )
			for ( val1 in dp1$unique_vals )
				add result$unique_vals[val1];
		if ( dp2?$unique_vals )
			for ( val2 in dp2$unique_vals )
				add result$unique_vals[val2];
			}
			
	return result;
	}
	
function write_log(ts: time, filter: Filter, data: MetricTable)
	{
	for ( index in data )
		{
		local val = 0;
		if ( data[index]?$unique_vals )
			val = |data[index]$unique_vals|;
		else
			val = data[index]$num;
		local m: Info = [$ts=ts,
		                 $ts_delta=filter$break_interval,
		                 $metric_id=filter$id,
		                 $filter_name=filter$name,
		                 $index=index,
		                 $value=val];
		
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
	if ( filter?$aggregation_table && filter?$aggregation_mask )
		{
		print "INVALID Metric filter: Defined $aggregation_table and $aggregation_mask.";
		return;
		}
	if ( [id, filter$name] in store )
		{
		print fmt("INVALID Metric filter: Filter with name \"%s\" already exists.", filter$name);
		return;
		}
	if ( !filter?$threshold_series &&  !filter?$default_threshold )
		{
		print "INVALID Metric filter: Must define one of $default_threshold and $threshold_series";
		return;
		}
	if ( filter?$threshold_series &&  filter?$custom_check_threshold )
		{
		print "INVALID Metric filter: Cannot define $custom_check_threshold with $threshold_series";
		return;
		}
	if ( filter?$threshold_series &&  filter?$default_threshold )
		{
		print "INVALID Metric filter: Cannot define both $default_threshold and $threshold_series";
		return;
		}
	if ( filter?$custom_check_threshold &&  !filter?$default_threshold )
		{
		print "INVALID Metric filter: Must define $default_threshold with $custom_check_threshold";
		return;
		}
	if ( !filter?$trigger_custom_check_threshold &&  filter?$custom_check_threshold )
		{
		print "INVALID Metric filter: You defined $trigger_custom_check_threshold but $custom_check_threshold is missing";
		return;
		}
	if ( !filter?$trigger_custom_check_threshold &&  filter?$custom_check_threshold )
		{
		print "WARNING Metric filter: You did not define $trigger_custom_check_threshold (default will be used)";
		}
	
	if ( ! filter?$id )
		filter$id = id;
	
	if ( id !in metric_filters )
		metric_filters[id] = vector();
	metric_filters[id][|metric_filters[id]|] = filter;

	filter_store[id, filter$name] = filter;
	store[id, filter$name] = table();
	
	schedule filter$break_interval { Metrics::log_it(filter) };
	}

function add_it(id: string, index: Index, integer_value: bool, num: count, str: string)
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
		if ( filter?$pred && ! filter$pred(index) )
			next;
		
		if ( index?$host )
			{
			if ( filter?$normalize_func )
				{
				index = filter$normalize_func(copy(index));
				}
			
			if ( filter?$aggregation_mask )
				{
				index$network = mask_addr(index$host, filter$aggregation_mask);
				delete index$host;
				}
			else if ( filter?$aggregation_table )
				{
				# Don't add the data if the aggregation table doesn't include 
				# the given host address.
				if ( index$host !in filter$aggregation_table )
					return;
				index$network = filter$aggregation_table[index$host];
				delete index$host;
				}
			}
		
		local metric_tbl = store[id, filter$name];
		if ( integer_value )
			{
			if ( index !in metric_tbl )
				metric_tbl[index] = [$num=0];
			metric_tbl[index]$num += num;
			data_added(filter, index, metric_tbl[index]$num);
			}
		else
			{
			if ( index !in metric_tbl )
				{
				local empty_ss: set[string] = set();
				metric_tbl[index] = [$unique_vals=empty_ss];
				}
			add metric_tbl[index]$unique_vals[str];
			#print metric_tbl[index]$unique_vals;
			#print "-------------------------------------";
			data_added(filter, index, |metric_tbl[index]$unique_vals|);
			}
		}
	}

function add_data(id: string, index: Index, increment: count)
	{
	add_it(id, index, T, increment, "");
	}
	
function add_unique(id: string, index: Index, data: string)
	{
	add_it(id, index, F, 0, data);
	}
	
function check_threshold(filter: Filter, index: Index, val: count): bool
	{
	local def_thresh = 0;

	if ( filter?$default_threshold )
		def_thresh = filter$default_threshold;
 
	if ( filter?$custom_check_threshold && ( val%filter$trigger_custom_check_threshold == 0 ) )
		return filter$custom_check_threshold( index, def_thresh, val );

	# No custom check threshold defined
	else if ( !filter?$custom_check_threshold )
		{
		if ( filter?$default_threshold )
			{
			if ( val > def_thresh)
				return T;
			}

		else if ( filter?$threshold_series )
			{
			if ( |filter$threshold_series| >= threshold_series_index[filter$id, filter$name, index] &&
			     val >= filter$threshold_series[threshold_series_index[filter$id, filter$name, index]] )
				return T;
			}
		}
	return F;
	}
		
function threshold_crossed_alert(filter: Filter, index: Index, val: count)
	{
	if ( filter?$threshold_crossed )
		filter$threshold_crossed( index, val );

	# If I don't reset here, the value just keeps
	# retriggering once the threshold has been exceeded
	if ( !filter?$threshold_series )
		reset(filter);
	else
		{
		# This just needs set to some value so that it doesn't refire the 
		# notice until it expires from the table or it crosses the next 
		# threshold in the case of vectors of thresholds.
		++threshold_series_index[filter$id, filter$name, index];
		}
	}
