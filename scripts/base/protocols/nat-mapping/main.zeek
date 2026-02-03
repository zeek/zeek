#@load ./spicy-events

module NATMapping;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register NAT-PMP and PCP for.
	const ports = {5351/tcp} &redef;

	## Record type containing the column fields of the Redis log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

}

event zeek_init() &priority=5
	{
	Log::create_stream(NATMapping::LOG, Log::Stream($columns=Info, $path="nat-mapping",
	    $policy=log_policy));

	Analyzer::register_for_ports(Analyzer::ANALYZER_NATMAPPING, ports);
	}
