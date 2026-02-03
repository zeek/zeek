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
		## Address of host that requested the mapping.
		int_addr: addr &log;
		## Internal port for the mapping.
		int_port: port &log;
		## External port for the mapping.
		ext_port: port &log;
		## Result of the mapping request.
		result: ResultCode &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Timeout to log requests without a response.
	const request_timeout = 30sec &redef;
}

function request_expire_callback(t: set[EventData], data: EventData) : interval {
	# request timed out, log it as such.
	Log::write(NATMapping::LOG, Info(
		$ts = network_time(),
		# TODO: pass over the connection ID
		$uid = "",
		$int_addr = data$internal_ip,
		$int_port = data$int_port,
		$ext_port = data$ext_port,
		$result = TIMEOUT));
}

global active_requests: set[EventData] &create_expire=request_timeout &expire_func=request_expire_callback;

event zeek_init() &priority=5
	{
	Log::create_stream(NATMapping::LOG, Log::Stream($columns=Info, $path="nat-mapping",
	    $policy=log_policy));

	Analyzer::register_for_ports(Analyzer::ANALYZER_NATMAPPING, ports);
	}

event map_request(c: connection, data: EventData)
	{
	# If the IP wasn't filled in via the initial request, use the originator's IP
	# instead. This is the case with NAT-PMP where the IP isn't part of the requested
	# data.
	if ( ! data?$internal_ip ) {
		data$internal_ip = c$id$orig_h;
	}

	if ( data in active_requests ) {
		delete active_requests[data];

		# request timed out, log it as such.
		Log::write(NATMapping::LOG, Info(
			$ts = network_time(),
			$uid = c$uid,
			$int_addr = data$internal_ip,
			$int_port = data$int_port,
			$ext_port = data$ext_port,
			$result = REREQUEST));
	}

	add active_requests[data];
	}

event map_response(c: connection, data: EventData, result: ResultCode)
	{
	if ( data in active_requests) {
		delete active_requests[data];
	}

	Log::write(NATMapping::LOG, Info(
		$ts = network_time(),
		$uid = c$uid,
		$int_addr = data$internal_ip,
		$int_port = data$int_port,
		$ext_port = data$ext_port,
		$result = result));
	}
