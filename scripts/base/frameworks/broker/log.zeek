@load ./main

module Broker;

export {
	## The Broker logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The type of a Broker activity being logged.
	type Type: enum {
		## An informational status update.
		STATUS,
		## An error situation.
		ERROR,
		## Fatal event, normal operation has most likely broken down.
		CRITICAL_EVENT,
		## Unrecoverable event that imparts at least part of the system.
		ERROR_EVENT,
		## Unexpected or conspicuous event that may still be recoverable.
		WARNING_EVENT,
		## Noteworthy event during normal operation.
		INFO_EVENT,
		## Information that might be relevant for a user to understand system behavior.
		VERBOSE_EVENT,
		## An event that is relevant only for troubleshooting and debugging.
		DEBUG_EVENT,
	};

	## A record type containing the column fields of the Broker log.
	type Info: record {
		## The network time at which a Broker event occurred.
		ts:                  time   &log;
		## The type of the Broker event.
		ty:                  Type &log;
		## The event being logged.
		ev:                  string &log;
		## The peer (if any) with which a Broker event is
		## concerned.
		peer:                NetworkInfo &log &optional;
		## An optional message describing the Broker event in more detail
		message:             string &log &optional;
	};
}

event zeek_init() &priority=5
	{
	Log::create_stream(Broker::LOG, Log::Stream($columns=Info, $path="broker", $policy=log_policy));
	}

function log_status(ev: string, endpoint: EndpointInfo, msg: string)
	{
	local r: Info;

	r = Broker::Info($ts = network_time(),
	                 $ev = ev,
	                 $ty = STATUS,
	                 $message = msg);

	if ( endpoint?$network )
		r$peer = endpoint$network;

	Log::write(Broker::LOG, r);
	}

event Broker::peer_added(endpoint: EndpointInfo, msg: string)
	{
	log_status("peer-added", endpoint, msg);
	}

event Broker::peer_removed(endpoint: EndpointInfo, msg: string)
	{
	log_status("peer-removed", endpoint, msg);
	}

event Broker::peer_lost(endpoint: EndpointInfo, msg: string)
	{
	log_status("connection-terminated", endpoint, msg);
	}

event Broker::error(code: ErrorCode, msg: string)
	{
	local ev = cat(code);
	ev = subst_string(ev, "Broker::", "");
	ev = subst_string(ev, "_", "-");
	ev = to_lower(ev);

	Log::write(Broker::LOG, Info($ts = network_time(),
	           $ev = ev,
	           $ty = ERROR,
	           $message = msg));

	Reporter::error(fmt("Broker error (%s): %s", code, msg));
	}

event Broker::internal_log_event(lvl: LogSeverityLevel, id: string, description: string)
	{
	local severity = Broker::CRITICAL_EVENT;
	switch lvl {
		case Broker::LOG_ERROR:
			severity = Broker::ERROR_EVENT;
			break;
		case Broker::LOG_WARNING:
			severity = Broker::WARNING_EVENT;
			break;
		case Broker::LOG_INFO:
			severity = Broker::INFO_EVENT;
			break;
		case Broker::LOG_VERBOSE:
			severity = Broker::VERBOSE_EVENT;
			break;
		case Broker::LOG_DEBUG:
			severity = Broker::DEBUG_EVENT;
			break;
	}
	Log::write(Broker::LOG, Info($ts = network_time(),
	           $ty = severity,
	           $ev = id,
	           $message = description));
	}
