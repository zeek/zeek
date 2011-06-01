##! This is the implementation of the metrics framework

module Metrics;

redef enum Log::ID += { METRICS };

export {
	type ID: enum {
		NO_DEFAULT_METRICS,
	};
	
	# TODO: create a metrics config logging stream to log the current 
	#       metrics configuration in case someone is looking through
	#       old logs and the configuration has changed since then.
	type Config: record {
		name:              ID &optional;
		## Global mask by which you'd like to aggregate traffic.
		aggregation_mask:  count                   &optional;
		## This is essentially applying names to various subnets.
		aggregation_table: table[subnet] of string &optional;
		break_interval:    interval                &default=5min;
	};
	
	type DataPlug: record {
		## Host is the value to which this metric applies.
		host:         addr &optional;
		
		## A non-host related metric or a sub-key for a host based metric.
		## An example might be successful SSH connections by client where the
		## client string would be the index value.
		## Another example might be number of HTTP requests to a particular 
		## value in a Host header.  This is an example of a non-host based
		## metric since multiple IP addresses could respond for the same Host
		## header value.
		index:        string &default="";
		
		## The value with which to increment the count of the metric.
		increment:    count &default=1;
	};
	
	type Info: record {
		ts:           time   &log;
		name:         ID     &log;
		index:        string &log &optional;
		agg_subnet:   string &log &optional;
		value:        count  &log;
	};
	
	global create: function(name: ID, config: Config);
	global add_data: function(name: ID, plug: DataPlug);
}

global metric_configs: table[ID] of Config = table();

type MetricIndex: table[string] of count &default=0;
type MetricTable: table[string] of MetricIndex;
global store: table[ID] of MetricTable = table();

event bro_init()
	{
	Log::create_stream(METRICS, [$columns=Info]);
	}
	
function reset(name: ID)
	{
	store[name] = table();
	}

event log_it(config: Config)
	{
	local name = config$name;
	for ( agg_subnet in store[name] )
		{
		local metric_values = store[name][agg_subnet];
		for ( index in metric_values )
			{
			local val = metric_values[index];
			local m: Info = [$ts=network_time(), $name=name, $agg_subnet=fmt("%s", agg_subnet), $index=index, $value=val];
			if ( index == "" )
				delete m$index;
			if ( agg_subnet == "" )
				delete m$agg_subnet;
			Log::write(METRICS, m);
			}
		}
	reset(name);
	schedule config$break_interval { log_it(config) };
	}

function create(name: ID, config: Config)
	{
	if ( config?$aggregation_table && config?$aggregation_mask )
		{
		print "INVALID Metric: Defined $aggregation_table and an $aggregation_mask.";
		return;
		}
	
	config$name = name;
	metric_configs[name] = config;
	store[name] = table();
	
	# Only do this on the manager if in a cluster.
	schedule config$break_interval { log_it(config) };
	}
	
function add_data(name: ID, plug: DataPlug)
	{
	local conf = metric_configs[name];

	local agg_subnet = "";
	if ( plug?$host )
		{
		if ( conf?$aggregation_mask )
			{
			local agg_mask = conf$aggregation_mask;
			local agg = mask_addr(plug$host, agg_mask);
			agg_subnet = fmt("%s/%d", agg, agg_mask);
			}
		else if ( conf?$aggregation_table )	
			agg_subnet = fmt("%s", conf$aggregation_table[plug$host]);
		}
	
	if ( agg_subnet !in store[name] )
		store[name][agg_subnet] = table([plug$index] = plug$increment);
	else
		{
		if ( plug$index !in store[name][agg_subnet] )
			store[name][agg_subnet][plug$index] = 0;
		store[name][agg_subnet][plug$index] = store[name][agg_subnet][plug$index] + plug$increment;
		}
	}
