global http_counter_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="monitored_http_requests",
	$unit="1",
	$help_text="Number of http requests observed"
]);

global http_counter = Telemetry::counter_with(http_counter_cf);

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{
	Telemetry::counter_inc(http_counter);
	}
