# @TEST-DOC: Using and listing of counters and gauges using the telemetry module.
# Note compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -Cr - %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC-FAIL: test -f reporter.log

@load base/frameworks/telemetry

global btest_a_cf = Telemetry::register_counter_family([
	$prefix="btest",
	$name="a_test",
	$unit="1",
	$help_text="A btest metric",
	$labels=vector("x", "y")
]);

global btest_b_cf = Telemetry::register_counter_family([
	$prefix="btest",
	$name="b_test",
	$unit="1",
	$help_text="Another btest metric",
	$labels=vector("x", "y")
]);

global btest_c_cf = Telemetry::register_counter_family([
	$prefix="btest",
	$name="c_test",
	$unit="1",
	$help_text="The last btest metric",
	$labels=vector("x", "y")
]);

global system_sensor_temp_gf = Telemetry::register_gauge_family([
	$prefix="system",
	$name="sensor_temperature",
	$unit="celsius",
	$help_text="Temperatures reported by sensors in the system",
	$labels=vector("name")
]);

global btest_sample_histogram_hf = Telemetry::register_histogram_family([
	$prefix="btest",
	$name="sample_histogram",
	$unit="1",
	$help_text="A sample histogram that is not returned by Telemetry::collect_metrics",
	$bounds=vector(1.0, 2.0, 3.0, 4.0, 5.0),
	$labels=vector("dim")
]);

function print_metrics(what: string, metrics: vector of Telemetry::Metric)
	{
	print fmt("### %s |%s|", what, |metrics|);
	for (i in metrics)
		{
		local m = metrics[i];
		print m$opts$metric_type, m$opts$name, m$opts$labels, m$labels, m$value;

		if (m?$count_value)
			print "count_value", m$count_value;
		}
	}

function print_histogram_metrics(what: string, metrics: vector of Telemetry::HistogramMetric)
	{
	print fmt("### %s |%s|", what, |metrics|);
	for (i in metrics)
		{
		local m = metrics[i];
		print m$opts$metric_type, m$opts$name, m$opts$bounds, m$opts$labels, m$labels, m$values, m$sum, m$observations;
		}
	}

event zeek_done() &priority=-100
	{
	Telemetry::counter_family_inc(btest_a_cf, vector("a", "b"));
	Telemetry::counter_family_inc(btest_a_cf, vector("a", "c"));
	Telemetry::counter_family_inc(btest_a_cf, vector("a", "c"));

	Telemetry::counter_family_inc(btest_b_cf, vector("a", "b"), 10.0);
	Telemetry::counter_family_inc(btest_b_cf, vector("a", "c"), 20.0);

	Telemetry::counter_family_set(btest_c_cf, vector("a", "b"), 100.0);
	Telemetry::counter_family_set(btest_c_cf, vector("a", "b"), 200.0);

	Telemetry::gauge_family_set(system_sensor_temp_gf, vector("cpu0"), 43.0);
	Telemetry::gauge_family_set(system_sensor_temp_gf, vector("cpu1"), 43.1);
	Telemetry::gauge_family_inc(system_sensor_temp_gf, vector("cpu1"));
	Telemetry::gauge_family_set(system_sensor_temp_gf, vector("cpu3"), 43.2);
	Telemetry::gauge_family_dec(system_sensor_temp_gf, vector("cpu3"));

	Telemetry::histogram_family_observe(btest_sample_histogram_hf, vector("a"), 0.5);
	Telemetry::histogram_family_observe(btest_sample_histogram_hf, vector("a"), 0.9);
	Telemetry::histogram_family_observe(btest_sample_histogram_hf, vector("a"), 1.1);
	Telemetry::histogram_family_observe(btest_sample_histogram_hf, vector("a"), 2.0);
	Telemetry::histogram_family_observe(btest_sample_histogram_hf, vector("a"), 7.0);

	Telemetry::histogram_family_observe(btest_sample_histogram_hf, vector("b"), 0.5);
	Telemetry::histogram_family_observe(btest_sample_histogram_hf, vector("b"), 7.0);

	local zeek_session_metrics = Telemetry::collect_metrics("zeek", "*session*");
	print_metrics("zeek_session_metrics", zeek_session_metrics);

	local all_btest_metrics = Telemetry::collect_metrics("bt*", "*");
	print_metrics("bt* metrics", all_btest_metrics);

	local btest_a_metrics = Telemetry::collect_metrics("btest", "a_*");
	print_metrics("btest_a_metrics", btest_a_metrics);

	local btest_b_metrics = Telemetry::collect_metrics("btest", "b_*");
	print_metrics("btest_b_metrics", btest_b_metrics);

	local system_metrics = Telemetry::collect_metrics("system");
	print_metrics("system_metrics", system_metrics);

	local histogram_metrics = Telemetry::collect_histogram_metrics("btest");
	print_histogram_metrics("btest_histogram_metrics", histogram_metrics);
	}
