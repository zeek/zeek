##! This script logs hosts that Bro determines have performed complete TCP 
##! handshakes and logs the address once per day (by default).  The log that 
##! is output provides an easy way to determine a count of the IP addresses in
##! use on a network per day.

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

module Known;

export {
	## The known-hosts logging stream identifier.
	redef enum Log::ID += { HOSTS_LOG };

	## The record type which contains the column fields of the known-hosts log.
	type HostsInfo: record {
		## The timestamp at which the host was detected.
		ts:      time &log;
		## The address that was detected originating or responding to a
		## TCP connection.
		host:    addr &log;
	};
	
	## The hosts whose existence should be logged and tracked.
	## See :bro:type:`Host` for possible choices.
	const host_tracking = LOCAL_HOSTS &redef;
	
	## The set of all known addresses to store for preventing duplicate 
	## logging of addresses.  It can also be used from other scripts to 
	## inspect if an address has been seen in use.
	## Maintain the list of known hosts for 24 hours so that the existence
	## of each individual address is logged each day.
	#global known_hosts: set[addr] &create_expire=1day &synchronized &redef;
	# FIXME how to ensure expiration with broker stores?
	global known_hosts: set[addr] &redef;
	global known_hosts_expire: interval = 1day &redef;

	## An event that can be handled to access the :bro:type:`Known::HostsInfo`
	## record as it is sent on to the logging framework.
	global log_known_hosts: event(rec: HostsInfo);
}

event bro_init()
	{
	Log::create_stream(Known::HOSTS_LOG, [$columns=HostsInfo, $ev=log_known_hosts, $path="known_hosts"]);
	}

event bro_init() &priority=-11
	{
	local k_hosts: set[string] = {};
	if(Cluster::is_enabled())
		{
		# FIXME ExpiryTime needs to be added
		local res = Broker::insert(Cluster::cluster_store, Broker::data("known_hosts"), Broker::data(k_hosts));
		}
	}

event connection_established(c: connection) &priority=5
	{
	local id = c$id;
	for ( host in set(id$orig_h, id$resp_h) )
		{
		if(Cluster::is_enabled())
			{
			if (c$orig$state == TCP_ESTABLISHED &&
					c$resp$state == TCP_ESTABLISHED &&
					addr_matches_host(host, host_tracking))
				{
				when (local res = Broker::exists(Cluster::cluster_store, Broker::data("known_hosts")))
					{
					local res_bool = Broker::refine_to_bool(res$result);

					if(res_bool)
						{
						when ( local res2 = Broker::lookup(Cluster::cluster_store, Broker::data("known_hosts")) )
							{
							local res2_bool = Broker::set_contains(res2$result, Broker::data(host));

							if(!res2_bool)
								{
								Broker::add_to_set(Cluster::cluster_store, Broker::data("known_hosts"), Broker::data(host));
								Log::write(Known::HOSTS_LOG, [$ts=network_time(), $host=host]);
								}
							}
						timeout 10sec
							{ print "timeout"; }
						}
					}
				timeout 20sec
					{ print "timeout"; }
				}
			}
		else if ( host !in known_hosts &&
					c$orig$state == TCP_ESTABLISHED &&
					c$resp$state == TCP_ESTABLISHED &&
					addr_matches_host(host, host_tracking) )
			{
			add known_hosts[host];
			Log::write(Known::HOSTS_LOG, [$ts=network_time(), $host=host]);
			}
		}
	}
