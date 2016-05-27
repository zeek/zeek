##! This script logs and tracks services.  In the case of this script, a service
##! is defined as an IP address and port which has responded to and fully 
##! completed a TCP handshake with another host.  If a protocol is detected
##! during the session, the protocol will also be logged.

@load base/utils/directions-and-hosts

module Known;

export {
	## The known-services logging stream identifier.
	redef enum Log::ID += { SERVICES_LOG };

	## The record type which contains the column fields of the known-services
	## log.
	type ServicesInfo: record {
		## The time at which the service was detected.
		ts:             time            &log;
		## The host address on which the service is running.
		host:           addr            &log;
		## The port number on which the service is running.
		port_num:       port            &log;
		## The transport-layer protocol which the service uses.
		port_proto:     transport_proto &log;
		## A set of protocols that match the service's connection payloads.
		service:        set[string]     &log;
	};
	
	## The hosts whose services should be tracked and logged.
	## See :bro:type:`Host` for possible choices.
	const service_tracking = LOCAL_HOSTS &redef;

	## Tracks the set of daily-detected services for preventing the logging
	## of duplicates, but can also be inspected by other scripts for
	## different purposes.
	global known_services: table[addr, port] of set[string] &create_expire=1day &synchronized;

	## Event that can be handled to access the :bro:type:`Known::ServicesInfo`
	## record as it is sent on to the logging framework.
	global log_known_services: event(rec: ServicesInfo);

	## Services that should be ignored.  Services that use dynamic ports
	## belong here.
	const ignored_services: set[string] = { "ftp-data", "gridftp-data" } &redef;
}

## Given two string sets determine if there is any overlap
function string_set_overlap(a: set[string], b: set[string]): bool
	{
	for (one in a) {
		if (one in b) {
			return T;
		}
	}
	return F;
}

event bro_init() &priority=5
	{
	Log::create_stream(Known::SERVICES_LOG, [$columns=ServicesInfo,
	                                         $ev=log_known_services,
	                                         $path="known_services"]);
	}
	
event connection_state_remove(c: connection) &priority=-5
	{
	if (|c$service| == 0 && /h/ !in c$history)
		return;
	local id = c$id;
	local a = id$resp_h;
	local p = id$resp_p;
	
	if ( ! addr_matches_host(a, service_tracking) ||
	     string_set_overlap(c$service, ignored_services) || # Don't include ignored services
	     ("DNS" in c$service && c$resp$size == 0) ) # for dns, require that the server talks.
		return;

	local added = F;
	if([a, p] !in known_services) {
		known_services[a,p] = set();
		added = T;
	}
	for(s in c$service)
		{
		if ( s !in known_services[a, p] )
			{
			added = T;
			add known_services[a, p][s];
			}
		}
	if(added)
		{
		local i: ServicesInfo;
		i$ts=network_time();
		i$host=a;
		i$port_num=p;
		i$port_proto=get_port_transport_proto(p);
		i$service=c$service;
		Log::write(Known::SERVICES_LOG, i);
		}
	}
