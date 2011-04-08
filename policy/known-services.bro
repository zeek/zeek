@load functions

module KnownServices;

redef enum Log::ID += { KNOWN_SERVICES };

export {
	type LogPoint: enum { 
		AFTER_PROTOCOL_DETECTION,
		AT_CONNECTION_END,
	};
	
	const default_log_point = AFTER_PROTOCOL_DETECTION &redef;
	

	type Info: record {
		ts:             time &log;
		host:           addr &log;
		port_num:       port &log;
		port_proto:     transport_proto &log;
		service:        set[string] &log &optional;
		
		log_point:      LogPoint &default=default_log_point;
	};
	
	# The hosts whose services should be logged.
	const logged_hosts = Enabled &redef;
	
	global known_services: set[addr, port] &create_expire=1day &synchronized;
	
	global log_known_services: event(rec: Info);
}

redef record connection += {
	known_services: Info &optional;
};

event bro_init()
	{
	Log::create_stream(KNOWN_SERVICES, [$columns=Info,
	                                    $ev=log_known_services]);
	}
	
function known_services_done(c: connection)
	{
	local id = c$id;
	if ( c?$known_services &&
	     [id$resp_h, id$resp_p] !in known_services &&
	     "ftp-data" !in c$service ) ##< don't include ftp data sessions
		{
		add known_services[id$resp_h, id$resp_p];
		c$known_services$service=c$service;
		Log::write(KNOWN_SERVICES, c$known_services);
		}
	}

event connection_established(c: connection) &priority=5
	{
	local id = c$id;
	if ( ! c?$known_services && 
	     addr_matches_hosts(id$resp_h, logged_hosts) )
		{
		local i: Info;
		i$ts=c$start_time;
		i$host=id$resp_h;
		i$port_num=id$resp_p;
		i$port_proto=get_port_transport_proto(id$resp_p);
		c$known_services = i;
		}
	}
	
event protocol_confirmation(c: connection, atype: count, aid: count) &priority=-5
	{
	if ( c?$known_services &&
	     c$known_services$log_point == AFTER_PROTOCOL_DETECTION )
		known_services_done(c);
	}

# Handle the connection ending in case no protocol was ever detected.
event connection_state_remove(c: connection) &priority=-5
	{
	known_services_done(c);
	}
