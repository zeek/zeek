global conn_durations_hf = Telemetry::register_histogram_family([
	$prefix="zeek",
	$name="monitored_connection_duration",
	$unit="seconds",
	$help_text="Duration of monitored connections",
	$bounds=vector(0.1, 1.0, 10.0, 30.0, 60.0),
	$label_names=vector("proto", "service")
]);

event connection_state_remove(c: connection)
	{
	local proto = cat(c$conn$proto);
	local service: set[string] = {"unknown"};

	if ( |c$service| != 0 )
		service = c$service;

	for (s in service )
		{
		local h = Telemetry::histogram_with(conn_durations_hf, vector(proto, to_lower(s)));
		Telemetry::histogram_observe(h, interval_to_double(c$duration));
		}
	}
