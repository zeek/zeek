@load functions
@load logging

module KnownHosts;

export {
	redef enum Log::ID += { KNOWN_HOSTS};
	type Log: record {
		ts:      time;
		address: addr;
	};

	# The hosts whose existence should be logged.
	# Choices are: LocalHosts, RemoteHosts, Enabled, Disabled
	const logging = Enabled &redef;
	
	# In case you are interested in more than logging just local assets
	# you can split the log file.
	#const split_log_file = F &redef;
	
	# Maintain the list of known hosts for 24 hours so that the existence
	# of each individual address is logged each day.
	global known_hosts: set[addr] &create_expire=1day;
}

event bro_init()
	{
	Log::create_stream("KNOWN_HOSTS", "KnownHosts::Log");
	Log::add_default_filter("KNOWN_HOSTS");
	}

event connection_established(c: connection)
	{
	local id = c$id;
	
	if ( id$orig_h !in known_hosts && addr_matches_hosts(id$orig_h, logging) )
		{
		add known_hosts[id$orig_h];
		Log::write("KNOWN_HOSTS", [$ts=network_time(), $address=id$orig_h]);
		}
	if ( id$resp_h !in known_hosts && addr_matches_hosts(id$resp_h, logging) )
		{
		add known_hosts[id$resp_h];
		Log::write("KNOWN_HOSTS", [$ts=network_time(), $address=id$resp_h]);
		}
	}
