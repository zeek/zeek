##! Module for recording and querying metrics. This modules wraps
##! the lower-level telemetry.bif functions.
##!
##! Metrics will be exposed through a Prometheus HTTP endpoint when
##! enabled by setting :zeek:see:`Broker::metrics_port` or using the
##! `BROKER_METRICS_PORT` environment variable.

@load base/misc/version
@load base/frameworks/telemetry/options

module Telemetry;

export {
	## Alias for a vector of label values.
	type labels_vector: vector of string;

	## Type that captures options used to create metrics.
	type MetricOpts: record {
		## The prefix (namespace) of the metric.
		prefix: string;

		## The human-readable name of the metric.
		name: string;

		## The unit of the metric. Set to a blank string if this is a unit-less metric.
		unit: string;

		## Documentation for this metric.
		help_text: string;

		## The label names (also called dimensions) of the metric. When
		## instantiating or working with concrete metrics, corresponding
		## label values have to be provided.
		labels: vector of string &default=vector();

		## Whether the metric represents something that is accumulating.
		## Defaults to ``T`` for counters and ``F`` for gauges and
		## histograms.
		is_total: bool &optional;

		## When creating a :zeek:see:`Telemetry::HistogramFamily`,
		## describes the number and bounds of the individual buckets.
		bounds: vector of double &optional;

		## The same meaning as *bounds*, but as :zeek:type:`count`.
		## Only set in the return value of
		## :zeek:see:`Telemetry::collect_histogram_metrics`.
		## for histograms when the underlying type is ``int64_t``,
		## otherwise ignored.
		count_bounds: vector of count &optional;

		## Describes the underlying metric type.
		## Only set in the return value of
		## :zeek:see:`Telemetry::collect_metrics` or
		## :zeek:see:`Telemetry::collect_histogram_metrics`,
		## otherwise ignored.
		metric_type: MetricType &optional;
	};

	## Type representing a family of counters with uninitialized label values.
	##
	## To create concrete :zeek:see:`Telemetry::Counter` instances, use
	## :zeek:see:`Telemetry::counter_with`. To modify counters directly
	## use :zeek:see:`Telemetry::counter_family_inc`.
	type CounterFamily: record {
		__family: opaque of dbl_counter_metric_family;
		__labels: vector of string;
	};

	## Type representing a counter metric with initialized label values.
	##
	## Counter metrics only ever go up and reset when the process
	## restarts. Use :zeek:see:`Telemetry::counter_inc` or
	## :zeek:see:`Telemetry::counter_set` to modify counters.
	## An example for a counter is the number of log writes
	## per :zeek:see:`Log::Stream` or number connections broken down
	## by protocol and service.
	type Counter: record {
		__metric: opaque of dbl_counter_metric;
	};

	## Register a counter family.
	global register_counter_family: function(opts: MetricOpts): CounterFamily;

	## Get a :zeek:see:`Telemetry::Counter` instance given family and label values.
	global counter_with: function(cf: CounterFamily,
	                              label_values: labels_vector &default=vector()): Counter;

	## Increment a :zeek:see:`Telemetry::Counter` by `amount`.
	## Using a negative `amount` is an error.
	##
	## c: The counter instance.
	##
	## amount: The amount by which to increment the counter.
	##
	## Returns: True if the counter was incremented successfully.
	global counter_inc: function(c: Counter, amount: double &default=1.0): bool;

	## Helper to set a :zeek:see:`Telemetry::Counter` to the given `value`.
	## This can be useful for mirroring counter metrics in an
	## :zeek:see:`Telemetry::sync` hook implementation.
	## Setting a value that is less than the current value of the
	## metric is an error and will be ignored.
	##
	## c: The counter instance.
	##
	## value: The value to set the counter to.
	##
	## Returns: True if the counter value was set successfully.
	global counter_set: function(c: Counter, value: double): bool;

	## Increment a :zeek:see:`Telemetry::Counter` through the :zeek:see:`Telemetry::CounterFamily`.
	## This is a short-cut for :zeek:see:`Telemetry::counter_inc`.
	## Using a negative amount is an error.
	##
	## cf: The counter family to use.
	##
	## label_values: The label values to use for the counter.
	##
	## amount: The amount by which to increment the counter.
	##
	## Returns: True if the counter was incremented successfully.
	global counter_family_inc: function(cf: CounterFamily,
	                                    label_values: labels_vector &default=vector(),
	                                    amount: double &default=1.0): bool;

	## Set a :zeek:see:`Telemetry::Counter` through the :zeek:see:`Telemetry::CounterFamily`.
	## This is a short-cut for :zeek:see:`Telemetry::counter_set`.
	## Setting a value that is less than the current value of the
	## metric is an error and will be ignored.
	##
	## cf: The counter family to use.
	##
	## label_values: The label values to use for the counter.
	##
	## value: The value to set the counter to.
	##
	## Returns: True if the counter value was set successfully.
	global counter_family_set: function(cf: CounterFamily,
	                                    label_values: labels_vector,
	                                    value: double): bool;

	## Type representing a family of gauges with uninitialized label values.
	##
	## Create concrete :zeek:see:`Telemetry::Gauge` instances with
	## :zeek:see:`Telemetry::gauge_with`, or use
	## :zeek:see:`Telemetry::gauge_family_inc` or
	## :zeek:see:`Telemetry::gauge_family_set` directly.
	type GaugeFamily: record {
		__family: opaque of dbl_gauge_metric_family;
		__labels: vector of string;
	};

	## Type representing a gauge metric with initialized label values.
	##
	## Use :zeek:see:`Telemetry::gauge_inc`, :zeek:see:`Telemetry::gauge_dec`,
	## or :zeek:see:`Telemetry::gauge_set` to modify the gauge.
	## Example for gauges are process memory usage, table sizes
	## or footprints of long-lived values as determined by
	## :zeek:see:`val_footprint`.
	type Gauge: record {
		__metric: opaque of dbl_gauge_metric;
	};

	## Register a gauge family.
	global register_gauge_family: function(opts: MetricOpts): GaugeFamily;


	## Get a :zeek:see:`Telemetry::Gauge` instance given family and label values.
	global gauge_with: function(gf: GaugeFamily,
	                            label_values: labels_vector &default=vector()): Gauge;

	## Increment a :zeek:see:`Telemetry::Gauge` by `amount`.
	##
	## g: The gauge instance.
	##
	## amount: The amount by which to increment the gauge.
	##
	## Returns: True if the gauge was incremented successfully.
	global gauge_inc: function(g: Gauge, amount: double &default=1.0): bool;

	## Decrement a :zeek:see:`Telemetry::Gauge` by `amount`.
	##
	## g: The gauge instance.
	##
	## amount: The amount by which to decrement the gauge.
	##
	## Returns: True if the gauge was incremented successfully.
	global gauge_dec: function(g: Gauge, amount: double &default=1.0): bool;

	## Helper to set a :zeek:see:`Telemetry::Gauge` to the given `value`.
	##
	## g: The gauge instance.
	##
	## value: The value to set the gauge to.
	##
	## Returns: True if the gauge value was set successfully.
	global gauge_set: function(g: Gauge, value: double): bool;

	## Increment a :zeek:see:`Telemetry::Gauge` by the given `amount` through
	## the :zeek:see:`Telemetry::GaugeFamily`.
	## This is a short-cut for :zeek:see:`Telemetry::gauge_inc`.
	## Using a negative amount is an error.
	##
	## gf: The gauge family to use.
	##
	## label_values: The label values to use for the gauge.
	##
	## amount: The amount by which to increment the gauge.
	##
	## Returns: True if the gauge was incremented successfully.
	global gauge_family_inc: function(gf: GaugeFamily,
	                                  label_values: labels_vector &default=vector(),
	                                  amount: double &default=1.0): bool;

	## Decrement a :zeek:see:`Telemetry::Gauge` by the given `amount` through
	## the :zeek:see:`Telemetry::GaugeFamily`.
	## This is a short-cut for :zeek:see:`Telemetry::gauge_dec`.
	##
	## gf: The gauge family to use.
	##
	## label_values: The label values to use for the gauge.
	##
	## amount: The amount by which to increment the gauge.
	##
	## Returns: True if the gauge was incremented successfully.
	global gauge_family_dec: function(gf: GaugeFamily,
	                                  label_values: labels_vector &default=vector(),
	                                  amount: double &default=1.0): bool;

	## Set a :zeek:see:`Telemetry::Gauge` to the given `value` through
	## the :zeek:see:`Telemetry::GaugeFamily`.
	## This is a short-cut for :zeek:see:`Telemetry::gauge_set`.
	##
	## gf: The gauge family to use.
	##
	## label_values: The label values to use for the gauge.
	##
	## value: The value to set the gauge to.
	##
	## Returns: True if the gauge value was set successfully.
	global gauge_family_set: function(g: GaugeFamily,
	                                  label_values: labels_vector,
	                                  value: double): bool;

	## Type representing a family of histograms with uninitialized label values.
	## Create concrete :zeek:see:`Telemetry::Histogram` instances with
	## :zeek:see:`Telemetry::histogram_with` or use
	## :zeek:see:`Telemetry::histogram_family_observe` directly.
	type HistogramFamily: record {
		__family: opaque of dbl_histogram_metric_family;
		__labels: vector of string;
	};

	## Type representing a histogram metric with initialized label values.
	## Use :zeek:see:`Telemetry::histogram_observe` to make observations.
	type Histogram: record {
		__metric: opaque of dbl_histogram_metric;
	};

	## Register a histogram family.
	global register_histogram_family: function(opts: MetricOpts): HistogramFamily;

	## Get a :zeek:see:`Telemetry::Histogram` instance given family and label values.
	global histogram_with: function(hf: HistogramFamily,
	                                label_values: labels_vector &default=vector()): Histogram;

	## Observe a measurement for a :zeek:see:`Telemetry::Histogram`.
	##
	## h: The histogram instance.
	##
	## measurement: The value for this observations.
	##
	## Returns: True if measurement was observed successfully.
	global histogram_observe: function(h: Histogram, measurement: double): bool;

	## Observe a measurement for a :zeek:see:`Telemetry::Histogram` through
	## the :zeek:see:`Telemetry::HistogramFamily`.
	## This is a short-cut for :zeek:see:`Telemetry::histogram_observe`.
	##
	## hf: The histogram family to use.
	##
	## label_values: The label values to use for the histogram.
	##
	## measurement: The value for this observations.
	##
	## Returns: True if measurement was observed successfully.
	global histogram_family_observe: function(hf: HistogramFamily,
	                                          label_values: labels_vector,
	                                          measurement: double): bool;

	## Telemetry sync hook.
	##
	## This hook is invoked every :zeek:see:`Telemetry::sync_interval`
	## for script writers to synchronize or mirror metrics with the
	## telemetry subsystem. For example, when tracking table or value
	## footprints with gauges, the value in question can be set on an actual
	## :zeek:see:`Telemetry::Gauge` instance during execution of this hook.
	##
	## Implementations should be lightweight, this hook may be called
	## multiple times per minute. The interval can increased by changing
	## :zeek:see:`Telemetry::sync_interval` at the cost of delaying
	## metric updates and thereby reducing granularity.
	global sync: hook();

	## Interval at which the :zeek:see:`Telemetry::sync` hook is invoked.
	option sync_interval = 10sec;

	## Type of elements returned by the :zeek:see:`Telemetry::collect_metrics` function.
	type Metric: record {
		## A :zeek:see:`Telemetry::MetricOpts` record describing this metric.
		opts: MetricOpts;

		## The label values associated with this metric, if any.
		labels: vector of string;

		## The value of gauge or counter cast to a double
		## independent of the underlying data type.
		## This value is set for all counter and gauge metrics,
		## it is unset for histograms.
		value: double &optional;

		## The value of the underlying gauge or counter as a double
		## if the underlying metric type uses ``int64_t``.
		## Only counters and gauges created with the C++ API may
		## have this value set.
		count_value: count &optional;
	};

	## Type of elements returned by the :zeek:see:`Telemetry::collect_histogram_metrics` function.
	type HistogramMetric: record {
		## A :zeek:see:`Telemetry::MetricOpts` record describing this histogram.
		opts: MetricOpts;

		## The label values associated with this histogram, if any.
		labels: vector of string;

		## Individual counters for each of the buckets as
		## described by the *bounds* field in *opts*;
		values: vector of double;

		## If the underlying data type of the histogram is ``int64_t``,
		## this vector will hold the values as counts, otherwise it
		## is unset. Only histograms created with the C++ API have
		## may have this value set.
		count_values: vector of count &optional;

		## The number of observations made for this histogram.
		observations: double;

		## The sum of all observations for this histogram.
		sum: double;

		## If the underlying data type of the histogram is ``int64_t``,
		## the number of observations as :zeek:type:`count`, otherwise
		## unset.
		count_observations: count &optional;

		## If the underlying data type of the histogram is ``int64_t``,
		## the sum of all observations as :zeek:type:`count`, otherwise
		## unset.
		count_sum: count &optional;
	};

	type MetricVector : vector of Metric;

	## Collect all counter and gauge metrics matching the given *name* and *prefix*.
	##
	## For histogram metrics, use the :zeek:see:`Telemetry::collect_histogram_metrics`.
	##
	## The *prefix* and *name* parameters support globbing. By default,
	## all counters and gauges are returned.
	global collect_metrics: function(prefix: string &default="*",
	                                 name: string &default="*"): vector of Metric;

	## Collect all histograms and their observations matching the given
	## *prefix* and *name*.
	##
	## The *prefix* and *name* parameters support globbing. By default,
	## all histogram metrics are returned.
	global collect_histogram_metrics: function(prefix: string &default="*",
	                                           name: string &default="*"): vector of HistogramMetric;
}

## Internal helper to create the labels table.
function make_labels(keys: vector of string, values: labels_vector): table[string] of string
	{
	local labels: table[string] of string;
	for ( i in keys )
		labels[keys[i]] = values[i];

	return labels;
	}

function register_counter_family(opts: MetricOpts): CounterFamily
	{
	local f = Telemetry::__dbl_counter_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$help_text,
		opts$unit,
		opts?$is_total ? opts$is_total : T
	);
	return CounterFamily($__family=f, $__labels=opts$labels);
	}

# Fallback Counter returned when there are issues with the labels.
global error_counter_cf = register_counter_family([
	$prefix="zeek",
	$name="telemetry_counter_usage_error",
	$unit="",
	$help_text="This counter is returned when label usage for counters is wrong. Check reporter.log if non-zero."
]);

function counter_with(cf: CounterFamily, label_values: labels_vector): Counter
	{
	if ( |cf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |cf$__labels|, |label_values|));
		return counter_with(error_counter_cf);
		}

	local labels = make_labels(cf$__labels, label_values);
	local m = Telemetry::__dbl_counter_metric_get_or_add(cf$__family, labels);
	return Counter($__metric=m);
	}

function counter_inc(c: Counter, amount: double): bool
	{
	return Telemetry::__dbl_counter_inc(c$__metric, amount);
	}

function counter_set(c: Counter, value: double): bool
	{
	local cur_value: double = Telemetry::__dbl_counter_value(c$__metric);
	if (value < cur_value)
		{
		Reporter::error(fmt("Attempted to set lower counter value=%s cur_value=%s", value, cur_value));
		return F;
		}
	return Telemetry::__dbl_counter_inc(c$__metric, value - cur_value);
	}

function counter_family_inc(cf: CounterFamily, label_values: labels_vector, amount: double): bool
	{
	return counter_inc(counter_with(cf, label_values), amount);
	}

function counter_family_set(cf: CounterFamily, label_values: labels_vector, value: double): bool
	{
	return counter_set(counter_with(cf, label_values), value);
	}

function register_gauge_family(opts: MetricOpts): GaugeFamily
	{
	local f = Telemetry::__dbl_gauge_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$help_text,
		opts$unit,
		opts?$is_total ? opts$is_total : F
	);
	return GaugeFamily($__family=f, $__labels=opts$labels);
	}

# Fallback Gauge returned when there are issues with the label usage.
global error_gauge_cf = register_gauge_family([
	$prefix="zeek",
	$name="telemetry_gauge_usage_error",
	$unit="",
	$help_text="This gauge is returned when label usage for gauges is wrong. Check reporter.log if non-zero."
]);

function gauge_with(gf: GaugeFamily, label_values: labels_vector): Gauge
	{
	if ( |gf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |gf$__labels|, |label_values|));
		return gauge_with(error_gauge_cf);
		}
	local labels = make_labels(gf$__labels, label_values);
	local m = Telemetry::__dbl_gauge_metric_get_or_add(gf$__family, labels);
	return Gauge($__metric=m);
	}

function gauge_inc(g: Gauge, amount: double &default=1.0): bool
	{
	return Telemetry::__dbl_gauge_inc(g$__metric, amount);
	}

function gauge_dec(g: Gauge, amount: double &default=1.0): bool
	{
	return Telemetry::__dbl_gauge_dec(g$__metric, amount);
	}

function gauge_set(g: Gauge, value: double): bool
	{
	# Telemetry currently does not implement __dbl_gauge_set(), do
	# it by hand here.
	local cur_value: double = Telemetry::__dbl_gauge_value(g$__metric);
	if (value > cur_value)
		return Telemetry::__dbl_gauge_inc(g$__metric, value - cur_value);

	return Telemetry::__dbl_gauge_dec(g$__metric, cur_value - value);
	}

function gauge_family_inc(gf: GaugeFamily, label_values: labels_vector, value: double): bool
	{
	return gauge_inc(gauge_with(gf, label_values), value);
	}

function gauge_family_dec(gf: GaugeFamily, label_values: labels_vector, value: double): bool
	{
	return gauge_dec(gauge_with(gf, label_values), value);
	}

function gauge_family_set(gf: GaugeFamily, label_values: labels_vector, value: double): bool
	{
	return gauge_set(gauge_with(gf, label_values), value);
	}

function register_histogram_family(opts: MetricOpts): HistogramFamily
	{
	local f = Telemetry::__dbl_histogram_family(
		opts$prefix,
		opts$name,
		opts$labels,
		opts$bounds,
		opts$help_text,
		opts$unit,
		opts?$is_total ? opts$is_total : F
	);
	return HistogramFamily($__family=f, $__labels=opts$labels);
	}

# Fallback Histogram when there are issues with the labels.
global error_histogram_hf = register_histogram_family([
	$prefix="zeek",
	$name="telemetry_histogram_usage_error",
	$unit="",
	$help_text="This histogram is returned when label usage for histograms is wrong. Check reporter.log if non-zero.",
	$bounds=vector(1.0)
]);

function histogram_with(hf: HistogramFamily, label_values: labels_vector): Histogram
	{
	if ( |hf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |hf$__labels|, |label_values|));
		return histogram_with(error_histogram_hf);
		}

	local labels = make_labels(hf$__labels, label_values);
	local m = Telemetry::__dbl_histogram_metric_get_or_add(hf$__family, labels);
	return Histogram($__metric=m);
	}

function histogram_observe(h: Histogram, measurement: double): bool
	{
	return Telemetry::__dbl_histogram_observe(h$__metric, measurement);
	}

function histogram_family_observe(hf: HistogramFamily, label_values: labels_vector, measurement: double): bool
	{
	return histogram_observe(histogram_with(hf, label_values), measurement);
	}

function collect_metrics(prefix: string, name: string): vector of Metric
	{
	return Telemetry::__collect_metrics(prefix, name);
	}

function collect_histogram_metrics(prefix: string, name: string): vector of HistogramMetric
	{
	return Telemetry::__collect_histogram_metrics(prefix, name);
	}

event run_sync_hook()
	{
	hook Telemetry::sync();
	schedule sync_interval { run_sync_hook() };
	}

# Expose the Zeek version as Prometheus style info metric
global version_gauge_family = Telemetry::register_gauge_family([
	$prefix="zeek",
	$name="version_info",
	$unit="",
	$help_text="The Zeek version",
	$labels=vector("version_number", "major", "minor", "patch", "commit",
                       "beta", "debug","version_string")
]);

event zeek_init()
	{
	schedule sync_interval { run_sync_hook() };

	local v = Version::info;
	local labels = vector(cat(v$version_number),
	                      cat(v$major), cat(v$minor), cat (v$patch),
	                      cat(v$commit),
	                      v$beta ? "true" : "false",
	                      v$debug ? "true" : "false",
	                      v$version_string);

	Telemetry::gauge_family_set(version_gauge_family, labels, 1.0);
	}
