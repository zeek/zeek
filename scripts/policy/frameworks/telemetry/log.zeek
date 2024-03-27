##! Implementation of a telemetry.log and telemetry_histogram.log file
##! using metrics accessible via the Telemetry module.

@load base/frameworks/telemetry

module Telemetry;

export {
	redef enum Log::ID += { LOG, LOG_HISTOGRAM };

	## How often metrics are reported.
	option log_interval = 60sec;

	## Only metrics with prefixes in this set will be included in the
	## `telemetry.log` and `telemetry_histogram.log` files by default.
	## Setting this option to an empty set includes all prefixes.
	##
	## For more fine-grained customization, setting this option to an
	## empty set and implementing the :zeek:see:`Telemetry::log_policy`
	## and :zeek:see:`Telemetry::log_policy_histogram` hooks to filter
	## individual records is recommended.
	option log_prefixes: set[string] = {"process", "zeek"};

	## Record type used for logging counter and gauge metrics.
	type Info: record {
		## Timestamp of reporting.
		ts: time &log;

		## Peer that generated this log.
		peer: string &log;

		## Contains the value "counter" or "gauge" depending on
		## the underlying metric type.
		metric_type: string &log;

		## The prefix (namespace) of the metric.
		prefix: string &log &optional;

		## The name of the metric.
		name: string &log;

		## The unit of this metric, or unset if unit-less.
		unit: string &log &optional;

		## The names of the individual labels.
		labels: vector of string &log;

		## The values of the labels as listed in ``labels``.
		label_values: vector of string &log;

		## The value of this metric.
		value: double &log;
	};

	## Record type used for logging histogram metrics.
	type HistogramInfo: record {
		## Timestamp of reporting.
		ts: time &log;

		## Peer that generated this log.
		peer: string &log;

		## The prefix (namespace) of the metric.
		prefix: string &log &optional;

		## The name of the metric.
		name: string &log;

		## The unit of this metric, or unset if unit-less.
		unit: string &log &optional;

		## The names of the individual labels.
		labels: vector of string &log;

		## The values of the labels as listed in ``labels``.
		label_values: vector of string &log;

		## The bounds of the individual buckets
		bounds: vector of double &log;

		## The number of observations within each individual bucket.
		values: vector of double &log;

		## The sum over all observations
		sum: double &log;

		## The total number of observations.
		observations: double &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## A default logging policy hook for the histogram stream.
	global log_policy_histogram: Log::PolicyHook;

	## Event triggered for every record in the stream.
	global log_telemetry: event(rec: Info);

	## Event triggered for every record in the histogram stream.
	global log_telemetry_histogram: event(rec: HistogramInfo);
}

function do_log()
	{
	local ts = network_time();

	## TODO: this is potentially slow, since it requires looping over all of the metrics for each
	## prefix, and then doing it again for all of the histograms multiple times.
	local metrics : vector of Telemetry::Metric;
	if ( |log_prefixes| > 0 )
		{
		for ( prefix in log_prefixes )
			{
			metrics += Telemetry::collect_metrics(fmt("%s*", prefix), "*");
			}
		}
	else
		{
		metrics = Telemetry::collect_metrics();
		}

	for ( i in metrics )
		{
		local m = metrics[i];

		# Histograms don't have single values, skip over them.
		if ( m$opts$metric_type == DOUBLE_HISTOGRAM || m$opts$metric_type == INT_HISTOGRAM )
			next;

		# Render the metric_type as a short string. Unknown
		# shouldn't really happen, but lets have a fallback.
		local metric_type = "unknown";
		switch ( m$opts$metric_type ) {
			case DOUBLE_COUNTER, INT_COUNTER:
				metric_type = "counter";
				break;
			case DOUBLE_GAUGE, INT_GAUGE:
				metric_type = "gauge";
				break;
		}

		local rec = Info($ts=ts,
		                 $peer=peer_description,
		                 $metric_type=metric_type,
		                 $name=m$opts$name,
		                 $labels=m$opts$labels,
		                 $label_values=m$labels,
		                 $value=m$value);

		if ( m$opts?$unit && m$opts$unit != "" )
			rec$unit = m$opts$unit;

		Log::write(LOG, rec);
		}

	# Logging of histograms.
	ts = network_time();

	local histogram_metrics : vector of Telemetry::HistogramMetric;
	if ( |log_prefixes| > 0 )
		{
		for ( prefix in log_prefixes )
			{
			histogram_metrics += Telemetry::collect_histogram_metrics(fmt("%s*", prefix), "*");
			}
		}
	else
		{
		histogram_metrics = Telemetry::collect_histogram_metrics();
		}

	for ( i in histogram_metrics )
		{
		local hm = histogram_metrics[i];

		local hrec = HistogramInfo($ts=ts,
		                           $peer=peer_description,
		                           $name=hm$opts$name,
		                           $labels=hm$opts$labels,
		                           $label_values=hm$labels,
		                           $bounds=hm$opts$bounds,
		                           $values=hm$values,
		                           $sum=hm$sum,
		                           $observations=hm$observations);

		if ( hm$opts?$unit && hm$opts$unit != "" )
			hrec$unit = hm$opts$unit;

		Log::write(LOG_HISTOGRAM, hrec);
		}
	}

event Telemetry::log()
	{
	# We explicitly log once during zeek_done(), so short-circuit
	# here when we're already in the process of shutting down.
	if ( zeek_is_terminating() )
		return;

	do_log();
	schedule log_interval { Telemetry::log() };
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_telemetry, $path="telemetry", $policy=log_policy]);
	Log::create_stream(LOG_HISTOGRAM, [$columns=HistogramInfo, $ev=log_telemetry_histogram, $path="telemetry_histogram", $policy=log_policy_histogram]);

	schedule log_interval { Telemetry::log() };
	}

# Log late during zeek_done() once more. Any metric updates
# afterwards won't be visible in the log.
event zeek_done() &priority=-1000
	{
	do_log();
	}
