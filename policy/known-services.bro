#@load global-ext
@load functions

module KnownServices;

export {
	redef enum Log::ID += { KNOWN_SERVICES };
	type Log: record {
		ts:             time;
		host:           addr;
		port_num:       port;
#		port_num:       count;		# split 'em?
#		port_proto:     string;
		service:        string &default="";
	};

	# The hosts whose services should be logged.
	const logged_hosts = LocalHosts &redef;

	global known_services: set[addr, port] &create_expire=1day &synchronized;
}

# The temporary holding place for new, unknown services.
global established_conns: set[addr, port] &create_expire=1day &redef;


event bro_init()
	{
	Log::create_stream("KNOWN_SERVICES", "KnownServices::Log");
	Log::add_default_filter("KNOWN_SERVICES");
	}

event connection_established(c: connection)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in established_conns && 
	     addr_matches_hosts(id$resp_h, logged_hosts) )
		add established_conns[id$resp_h, id$resp_p];
	}
	
event known_services_done(c: connection)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in known_services &&
	     [id$resp_h, id$resp_p] in established_conns &&
	     "ftp-data" !in c$service ) # don't include ftp data sessions
		{
		add known_services[id$resp_h, id$resp_p];
		Log::write( "KNOWN_SERVICES", [ $ts=c$start_time, $host=id$resp_h, 
		                                $port_num=id$resp_p, $service=c$service] );
		}
	}
	
event connection_state_remove(c: connection)
	{
	event known_services_done(c);
	}


event protocol_confirmation(c: connection, atype: count, aid: count) &priority=-10
	{
	event known_services_done(c);
	}


