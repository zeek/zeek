##! This script logs hosts that Bro determines have performed complete TCP 
##! handshakes and logs the address once per day (by default).  The log that 
##! output provides an easy way to determine a count of the IP addresses in
##! use on a network per day.

@load utils/directions-and-hosts

module KnownHosts;

redef enum Log::ID += { KNOWN_HOSTS };

export {
	type Log: record {
		## The timestamp at which the host was detected.
		ts:      time &log;
		## The address that was detected originating or responding to a TCP 
		## connection.
		host:    addr &log;
	};

	## The hosts whose existence should be logged and tracked.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS
	const asset_tracking = default_asset_tracking &redef;
	
	## The set of all known addresses to store for preventing duplicate 
	## logging of addresses.  It can also be used from other scripts to 
	## inspect if an address has been seen in use.
	## Maintain the list of known hosts for 24 hours so that the existence
	## of each individual address is logged each day.
	global known_hosts: set[addr] &create_expire=1day &synchronized &redef;
	
	global log_known_hosts: event(rec: Log);
}

event bro_init()
	{
	Log::create_stream(KNOWN_HOSTS, [$columns=Log, $ev=log_known_hosts]);
	}

event connection_established(c: connection) &priority=5
	{
	local id = c$id;
	
	for ( host in set(id$orig_h, id$resp_h) )
		{
		if ( host !in known_hosts && addr_matches_hosts(host, asset_tracking) )
			{
			add known_hosts[host];
			Log::write(KNOWN_HOSTS, [$ts=network_time(), $host=host]);
			}
		}
	}
