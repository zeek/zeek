##! This script logs and tracks services.  In the case of this script, a service
##! is defined as an IP address and port which has responded to and fully 
##! completed a TCP handshake with another host.  If a protocol is detected
##! during the session, the protocol will also be logged.

@load utils/directions-and-hosts

module KnownServices;

redef enum Log::ID += { KNOWN_SERVICES };

export {
	type Info: record {
		ts:             time            &log;
		host:           addr            &log;
		port_num:       port            &log;
		port_proto:     transport_proto &log;
		service:        set[string]     &log;
		
		done:           bool &default=F;
	};
	
	## The hosts whose services should be tracked and logged.
	const asset_tracking = LOCAL_HOSTS &redef;
	
	global known_services: set[addr, port] &create_expire=1day &synchronized;
	
	global log_known_services: event(rec: Info);
}

redef record connection += {
	known_services_done: bool &default=F;
};

event bro_init()
	{
	Log::create_stream(KNOWN_SERVICES, [$columns=Info,
	                                    $ev=log_known_services]);
	}
	
function known_services_done(c: connection)
	{
	local id = c$id;
	if ( ! c$known_services_done &&
	     addr_matches_host(id$resp_h, asset_tracking) &&
	     [id$resp_h, id$resp_p] !in known_services &&
	     "ftp-data" !in c$service ) # don't include ftp data sessions
		{
		local i: Info;
		i$ts=c$start_time;
		i$host=id$resp_h;
		i$port_num=id$resp_p;
		i$port_proto=get_port_transport_proto(id$resp_p);
		i$service=c$service;
		
		add known_services[id$resp_h, id$resp_p];
		Log::write(KNOWN_SERVICES, i);
		c$known_services_done = T;
		}
	}
	
event protocol_confirmation(c: connection, atype: count, aid: count) &priority=-5
	{
	known_services_done(c);
	}

# Handle the connection ending in case no protocol was ever detected.
event connection_state_remove(c: connection) &priority=-5
	{
	known_services_done(c);
	}
