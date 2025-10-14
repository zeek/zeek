global log_writes_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="log_writes",
	$unit="1",
	$help_text="Number of log writes per stream",
	$label_names=vector("log_id")
]);

global log_writes: table[Log::ID] of count &default=0;

hook Log::log_stream_policy(rec: any, id: Log::ID)
	{
	++log_writes[id];
	}

hook Telemetry::sync()
	{
	for ( id, v in log_writes )
		{
		local log_id = to_lower(gsub(cat(id), /:+/, "_"));
		Telemetry::counter_family_inc(log_writes_cf, vector(log_id));
		}
	}
