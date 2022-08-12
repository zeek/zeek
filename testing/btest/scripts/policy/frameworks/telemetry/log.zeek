# @TEST-DOC: Test loading of telemetry/log and smoke check the telemetry.log file
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -Cr - %INPUT > out
# @TEST-EXEC: grep 'zeek.*sessions' telemetry.log > telemetry.log.filtered
# @TEST-EXEC: grep 'zeek.*connection_duration' telemetry_histogram.log > telemetry_histogram.log.filtered

# @TEST-EXEC: btest-diff telemetry.log.filtered
# @TEST-EXEC: btest-diff telemetry_histogram.log.filtered

@load frameworks/telemetry/log


global connection_duration_hf = Telemetry::register_histogram_family([
	$prefix="zeek",
	$name="connection_duration",
	$unit="seconds",
	$help_text="Monitored connection duration",
	$bounds=vector(2.0, 3.0, 4.0, 5.0, 6.0, 10.0)
]);

global connection_duration_h = Telemetry::histogram_with(connection_duration_hf);

event connection_state_remove(c: connection)
	{
	Telemetry::histogram_observe(connection_duration_h, interval_to_double(c$duration));
	}
