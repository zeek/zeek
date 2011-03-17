@load functions

module KnownServices;

redef enum Log::ID += { KNOWN_SERVICES };

export {
	type LogPoint: enum { 
		AFTER_PROTOCOL_DETECTION,
		AT_CONNECTION_END,
	};

	type Log: record {
		ts:             time;
		host:           addr;
		port_num:       port;
		port_proto:     transport_proto;
		service:        set[string];
	};
	
	type Info: record {
		log:       Log;
		log_point: LogPoint;
	};
	
	# The hosts whose services should be logged.
	const logged_hosts = LocalHosts &redef;
	
	const default_log_point = AFTER_PROTOCOL_DETECTION &redef;

	global known_services: set[addr, port] &create_expire=1day &synchronized;
	
	global log_known_services: event(rec: Log);
}

# The temporary holding place for new, unknown services.
global established_conns: table[addr, port] of Info &read_expire=1hour &redef;

event bro_init()
	{
	Log::create_stream(KNOWN_SERVICES, [$columns=KnownServices::Log, 
	                                    $ev=log_known_services]);
	Log::add_default_filter(KNOWN_SERVICES);
	}
	
function known_services_done(c: connection)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in known_services &&
	     [id$resp_h, id$resp_p] in established_conns &&
	     "ftp-data" !in c$service ) # don't include ftp data sessions
		{
		add known_services[id$resp_h, id$resp_p];
		local log = established_conns[id$resp_h, id$resp_p]$log;
		log$service=c$service;
		Log::write(KNOWN_SERVICES, log);
		}
	
	if ( [id$resp_h, id$resp_p] in established_conns )
		delete established_conns[id$resp_h, id$resp_p];
	}

event connection_established(c: connection) &priority=1
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in established_conns && 
	     addr_matches_hosts(id$resp_h, logged_hosts) )
		{
		local service_set: set[string] = set();
		local l: Log = [$ts=c$start_time,
		                $host=id$resp_h,
		                $port_num=id$resp_p,
		                $port_proto=get_port_transport_proto(id$resp_p),
		                $service=service_set];
		established_conns[id$resp_h, id$resp_p] = [$log=l, $log_point=default_log_point];
		}
	}
	
event protocol_confirmation(c: connection, atype: count, aid: count) &priority=-10
	{
	if ( [c$id$resp_h, c$id$resp_p] !in established_conns )
		return;
		
	local l = established_conns[c$id$resp_h, c$id$resp_p];
	if ( l$log_point == AFTER_PROTOCOL_DETECTION )
		known_services_done(c);
	}

# Handle the connection ending in case no protocol was ever detected.
event connection_state_remove(c: connection)
	{
	known_services_done(c);
	}
