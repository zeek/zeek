@load ./main

module Broker;

export {
	## The Broker logging stream identifier.
	redef enum Log::ID += { LOG };

	## The type of a Broker activity being logged.
	type Type: enum {
		## An informational status update.
		STATUS,
		## An error situation.
		ERROR
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
	Log::create_stream(Broker::LOG, [$columns=Info, $path="broker"]);
	}

function log_status(ev: string, endpoint: EndpointInfo, msg: string)
	{
	local r: Info;

	r = [$ts = network_time(),
	     $ev = ev,
	     $ty = STATUS,
	     $message = msg];

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

	Log::write(Broker::LOG, [$ts = network_time(),
	           $ev = ev,
	           $ty = ERROR,
	           $message = msg]);

	Reporter::error(fmt("Broker error (%s): %s", code, msg));
	}

