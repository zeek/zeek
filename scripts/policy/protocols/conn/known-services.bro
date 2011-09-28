##! This script logs and tracks services.  In the case of this script, a service
##! is defined as an IP address and port which has responded to and fully 
##! completed a TCP handshake with another host.  If a protocol is detected
##! during the session, the protocol will also be logged.

@load base/utils/directions-and-hosts

module Known;

export {
	redef enum Log::ID += { SERVICES_LOG };
	
	type ServicesInfo: record {
		ts:             time            &log;
		host:           addr            &log;
		port_num:       port            &log;
		port_proto:     transport_proto &log;
		service:        set[string]     &log;
		
		done:           bool &default=F;
	};
	
	## The hosts whose services should be tracked and logged.
	const service_tracking = LOCAL_HOSTS &redef;
	
	global known_services: set[addr, port] &create_expire=1day &synchronized;
	
	global log_known_services: event(rec: ServicesInfo);
}

redef record connection += {
	known_services_done: bool &default=F;
};

event bro_init() &priority=5
	{
	Log::create_stream(Known::SERVICES_LOG, [$columns=ServicesInfo,
	                                         $ev=log_known_services]);
	}
	
event log_it(ts: time, a: addr, p: port, services: set[string])
	{
	if ( [a, p] !in known_services )
		{
		add known_services[a, p];
	
		local i: ServicesInfo;
		i$ts=ts;
		i$host=a;
		i$port_num=p;
		i$port_proto=get_port_transport_proto(p);
		i$service=services;
		Log::write(Known::SERVICES_LOG, i);
		}
	}
	
function known_services_done(c: connection)
	{
	local id = c$id;
	c$known_services_done = T;
	
	if ( ! addr_matches_host(id$resp_h, service_tracking) ||
	     "ftp-data" in c$service ) # don't include ftp data sessions
		return;
	
	# If no protocol was detected, wait a short
	# time before attempting to log in case a protocol is detected
	# on another connection.
	if ( |c$service| == 0 )
		schedule 2mins { log_it(network_time(), id$resp_h, id$resp_p, c$service) };
	else 
		event log_it(network_time(), id$resp_h, id$resp_p, c$service);
	}
	
event protocol_confirmation(c: connection, atype: count, aid: count) &priority=-5
	{
	known_services_done(c);
	}

# Handle the connection ending in case no protocol was ever detected.
event connection_state_remove(c: connection) &priority=-5
	{
	if ( ! c$known_services_done && c$resp$state == TCP_ESTABLISHED )
		known_services_done(c);
	}
