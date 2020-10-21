##! Generates a log for what is being queried via ``whois``. Uses the
##! finger analyzers, see :rfc:`3912`.

module Whois;

export {
	## The Whois protocol logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type which contains the column fields of the DHCP log.
	type Info: record {
		## The earliest time a whois request or response was seen.
		ts:    time    &log;
		## A unique identifier of the connection
		uid:   string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:    conn_id &log;
		## Name that was queried
		query: string  &log &optional;
	};

	## Event that can be handled to access the whois
	## record as it is sent on to the logging framework.
	global log_whois: event(rec: Info);
}

const ports = { 43/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(Whois::LOG, [$columns=Info, $ev=log_whois, $path="whois", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_FINGER, ports);
	}

event finger_request(c: connection, full: bool, username: string, hostname: string)
	{
	add c$service["whois"];
	Log::write(Whois::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $query=username]);
	}

