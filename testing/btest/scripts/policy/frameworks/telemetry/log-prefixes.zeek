# @TEST-DOC: Tests that setting log_prefixes filters out the zeek metrics normally created.
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -Cr - %INPUT > out

# @TEST-EXEC: btest-diff telemetry.log
# @TEST-EXEC: btest-diff telemetry_histogram.log

@load frameworks/telemetry/log

redef Telemetry::log_prefixes = {"btest"};

global connections_by_proto_cf = Telemetry::register_counter_family([
	$prefix="btest",
	$name="connections",
	$unit="",
	$help_text="Total number of monitored connections",
	$labels=vector("proto")
]);

global connection_duration_hf = Telemetry::register_histogram_family([
	$prefix="btest",
	$name="connection_duration",
	$unit="seconds",
	$help_text="Monitored connection duration",
	$bounds=vector(2.0, 3.0, 4.0, 5.0, 6.0, 10.0)
]);

global connection_duration_h = Telemetry::histogram_with(connection_duration_hf);

event connection_state_remove(c: connection)
	{
	local proto = to_lower(cat(get_port_transport_proto(c$id$orig_p)));
	Telemetry::counter_family_inc(connections_by_proto_cf, vector(proto));
	Telemetry::histogram_observe(connection_duration_h, interval_to_double(c$duration));
	}
