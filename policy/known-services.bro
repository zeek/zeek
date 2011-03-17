@load functions

module KnownServices;

redef enum Log::ID += { KNOWN_SERVICES };

export {
	type LogPoints: enum { 
		AFTER_PROTOCOL_DETECTION,
		AT_CONNECTION_END,
	};

	type Log: record {
		ts:             time;
		host:           addr;
		port_num:       port;
		port_proto:     transport_proto;
		service:        set[string];
		log_point:      LogPoints;
	};
	
	
	# The hosts whose services should be logged.
	const logged_hosts = LocalHosts &redef;
	
	const default_log_point = AFTER_PROTOCOL_DETECTION &redef;

	global known_services: set[addr, port] &create_expire=1day &synchronized;
	
	global log_known_services: event(rec: Log);
}

# The temporary holding place for new, unknown services.
global established_conns: table[addr, port] of Log &create_expire=1day &redef;

event bro_init()
	{
	Log::create_stream(KNOWN_SERVICES, [$columns=KnownServices::Log, 
	                                    $ev=log_known_services]);
	Log::add_default_filter(KNOWN_SERVICES);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in established_conns && 
	     addr_matches_hosts(id$resp_h, logged_hosts) )
		add established_conns[id$resp_h, id$resp_p];
	}
	
function known_services_done(c: connection)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in known_services &&
	     [id$resp_h, id$resp_p] in established_conns &&
	     "ftp-data" !in c$service ) # don't include ftp data sessions
		{
		add known_services[id$resp_h, id$resp_p];
		Log::write(KNOWN_SERVICES, [$ts=c$start_time, 
		                            $host=id$resp_h, 
		                            $port_num=id$resp_p, 
		                            $port_proto=get_port_transport_proto(id$resp_p),
		                            $service=c$service] );
		}
	}
	
event connection_established(c: connection)
	{
	
	}
	
# Log the event after protocol detection if 
event protocol_confirmation(c: connection, atype: count, aid: count) &priority=-10
	{
	local l = established_conns[c$id$resp, c$id$resp_p];
	if ( l$log_point == AFTER_PROTOCOL_DETECTION )
		known_services_done(c);
	}

# Handle the connection ending in case no protocol was ever detected.
event connection_state_remove(c: connection)
	{
	known_services_done(c);
	}

