
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
	        ## The Broker event being logged.
                ev:                  string &log;
	        ## The type of the Broker event.
                ty:                  Type &log;
		## The peer (if any) with which a Broker event is
		## concerned.
		peer:                NetworkInfo &log &optional;
		## An optional message describing the Broker event in more detail
		message:             string &log &optional;
	};
}

event bro_init() &priority=5
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

event Broker::peer_recovered(endpoint: EndpointInfo, msg: string)
	{
	log_status("peer-recovered", endpoint, msg);
	}

event Broker::error(code: ErrorCode, msg: string)
	{
	Log::write(Broker::LOG, [$ts = network_time(),
				 $ev = "error",
				 $ty = ERROR,
				 $message = msg]);
	}

