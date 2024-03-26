# Note compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -Cr - %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC-FAIL: test -f reporter.log

@load base/frameworks/telemetry

global connection_duration_hf = Telemetry::register_histogram_family([
	$prefix="zeek",
	$name="connection_duration",
	$unit="seconds",
	$help_text="Monitored connection durations",
	$bounds=vector(2.0, 3.0, 4.0, 5.0, 6.0, 10.0)
]);

global realistic_connection_duration_hf = Telemetry::register_histogram_family([
	$prefix="zeek",
	$name="realistic_connection_duration",
	$labels=vector("proto"),
	$unit="seconds",
	$help_text="Monitored connection durations by protocol",
	$bounds=vector(0.1, 1.0, 10.0, 30.0, 60.0, 120.0, 300, 900.0, 1800.0)
]);

global connection_duration_h = Telemetry::histogram_with(connection_duration_hf);

event connection_state_remove(c: connection)
	{
	Telemetry::histogram_observe(connection_duration_h, interval_to_double(c$duration));
	local proto = to_lower(cat(get_port_transport_proto(c$id$resp_p)));
	Telemetry::histogram_family_observe(realistic_connection_duration_hf,
	                                    vector(proto),
	                                    interval_to_double(c$duration));
	}

event zeek_done() &priority=-100
	{
	local histogram_metrics = Telemetry::collect_histogram_metrics("zeek", "*connection_duration");
	for (i in histogram_metrics)
		{
		local hm = histogram_metrics[i];
		print hm$opts$metric_type, hm$opts$name;
		print hm$opts$labels;
		print hm$labels;
		print hm$opts$bounds;
		print hm$values;
		print hm$observations, hm$sum;
		}
	}
