global log_writes_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="log_writes",
	$unit="1",
	$help_text="Number of log writes per stream",
	$label_names=vector("log_id")
]);

# Cache for the Telemetry::Counter instances.
global log_write_counters: table[Log::ID] of Telemetry::Counter;

hook Log::log_stream_policy(rec: any, id: Log::ID)
	{
	if ( id !in log_write_counters )
		{
		local log_id = to_lower(gsub(cat(id), /:+/, "_"));
		log_write_counters[id] = Telemetry::counter_with(log_writes_cf,
		                                                 vector(log_id));
		}

	Telemetry::counter_inc(log_write_counters[id]);
	}
