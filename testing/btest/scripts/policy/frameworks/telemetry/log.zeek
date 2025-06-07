# @TEST-DOC: Test loading of telemetry/log and smoke check the telemetry.log file
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT > out
# @TEST-EXEC: grep -E 'zeek_(net|.*sessions)' telemetry.log > telemetry.log.filtered
# @TEST-EXEC: grep 'zeek.*connection_duration' telemetry_histogram.log > telemetry_histogram.log.filtered

# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff telemetry.log.filtered
# @TEST-EXEC: btest-diff telemetry_histogram.log.filtered

@load misc/stats
@load frameworks/telemetry/log

redef Telemetry::log_interval = 1sec;

global connection_duration_hf = Telemetry::register_histogram_family([
	$prefix="zeek",
	$name="connection_duration",
	$unit="seconds",
	$help_text="Monitored connection duration",
	$bounds=vector(0.0001, 0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0)
]);

global connection_duration_h = Telemetry::histogram_with(connection_duration_hf);

event connection_state_remove(c: connection)
	{
	Telemetry::histogram_observe(connection_duration_h, interval_to_double(c$duration));
	}
