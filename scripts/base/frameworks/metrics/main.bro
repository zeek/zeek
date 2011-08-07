##! This is the implementation of the metrics framework

module Metrics;

export {
	redef enum Log::ID += { METRICS };

	type ID: enum {
		ALL,
	};
	
	const default_aggregation_mask = 24 &redef;
	const default_break_interval = 5mins &redef;
	
	# TODO: configure a metrics filter logging stream to log the current
	#       metrics configuration in case someone is looking through
	#       old logs and the configuration has changed since then.
	type Filter: record {
		name:              ID                      &optional;
		## Global mask by which you'd like to aggregate traffic.
		aggregation_mask:  count                   &optional;
		## This is essentially applying names to various subnets.
		aggregation_table: table[subnet] of string &optional;
		break_interval:    interval                &default=default_break_interval;
	};
	
	type Index: record {
		## Host is the value to which this metric applies.
		host:         addr &optional;
		
		## A non-address related metric or a sub-key for an address based metric.
		## An example might be successful SSH connections by client IP address
		## where the client string would be the index value.
		## Another example might be number of HTTP requests to a particular
		## value in a Host header.  This is an example of a non-host based
		## metric since multiple IP addresses could respond for the same Host
		## header value.
		index:        string &default="";
	};
	
	type Info: record {
		ts:           time   &log;
		name:         ID     &log;
		index:        string &log &optional;
		agg_subnet:   string &log &optional;
		value:        count  &log;
	};
	
	global add_filter: function(name: ID, filter: Filter);
	global add_data: function(name: ID, index: Index, increment: count);
	
	global log_metrics: event(rec: Info);
}

global metric_filters: table[ID] of Filter = table();

type MetricIndex: table[string] of count &default=0;
type MetricTable: table[string] of MetricIndex;
global store: table[ID] of MetricTable = table();

event bro_init()
	{
	Log::create_stream(METRICS, [$columns=Info, $ev=log_metrics]);
	}
	
function reset(name: ID)
	{
	store[name] = table();
	}

event log_it(filter: Filter)
	{
	# If this node is the manager in a cluster, this needs to request values
	# for this metric from all of the workers.
	
	local name = filter$name;
	for ( agg_subnet in store[name] )
		{
		local metric_values = store[name][agg_subnet];
		for ( index in metric_values )
			{
			local val = metric_values[index];
			local m: Info = [$ts=network_time(), 
			                 $name=name, 
			                 $agg_subnet=fmt("%s", agg_subnet), 
			                 $index=index, 
			                 $value=val];
			if ( index == "" )
				delete m$index;
			if ( agg_subnet == "" )
				delete m$agg_subnet;
			Log::write(METRICS, m);
			}
		}
	
	
	reset(name);
	
	schedule filter$break_interval { log_it(filter) };
	}

function add_filter(name: ID, filter: Filter)
	{
	if ( filter?$aggregation_table && filter?$aggregation_mask )
		{
		print "INVALID Metric filter: Defined $aggregation_table and $aggregation_mask.";
		return;
		}
	
	filter$name = name;
	metric_filters[name] = filter;
	store[name] = table();
	
	# Only do this on the manager if in a cluster.
	schedule filter$break_interval { log_it(filter) };
	}
	
function add_data(name: ID, index: Index, increment: count)
	{
	local conf = metric_filters[name];

	local agg_subnet = "";
	if ( index?$host )
		{
		if ( conf?$aggregation_mask )
			{
			local agg_mask = conf$aggregation_mask;
			agg_subnet = fmt("%s", mask_addr(index$host, agg_mask));
			}
		else if ( conf?$aggregation_table )	
			agg_subnet = fmt("%s", conf$aggregation_table[index$host]);
		else
			agg_subnet = fmt("%s", index$host);
		}
	
	if ( agg_subnet !in store[name] )
		store[name][agg_subnet] = table();
	
	if ( index$index !in store[name][agg_subnet] )
		store[name][agg_subnet][index$index] = 0;
	store[name][agg_subnet][index$index] = store[name][agg_subnet][index$index] + increment;
	}
