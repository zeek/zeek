##! This script logs hosts that Zeek determines have performed complete TCP
##! handshakes and logs the address once per day (by default).  The log that
##! is output provides an easy way to determine a count of the IP addresses in
##! use on a network per day.

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

module Known;

export {
	## The known-hosts logging stream identifier.
	redef enum Log::ID += { HOSTS_LOG };

	## A default logging policy hook for the stream.
	global log_policy_hosts: Log::PolicyHook;

	## The record type which contains the column fields of the known-hosts log.
	type HostsInfo: record {
		## The timestamp at which the host was detected.
		ts:      time &log;
		## The address that was detected originating or responding to a
		## TCP connection.
		host:    addr &log;
	};

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Zeek set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_host_store = F &redef;

	## The hosts whose existence should be logged and tracked.
	## See :zeek:type:`Host` for possible choices.
	option host_tracking = LOCAL_HOSTS;

	## Holds the set of all known hosts.  Keys in the store are addresses
	## and their associated value will always be the "true" boolean.
	global host_store: Cluster::StoreInfo;

	## The Broker topic name to use for :zeek:see:`Known::host_store`.
	const host_store_name = "zeek/known/hosts" &redef;

	## The expiry interval of new entries in :zeek:see:`Known::host_store`.
	## This also changes the interval at which hosts get logged.
	const host_store_expiry = 1day &redef;

	## The timeout interval to use for operations against
	## :zeek:see:`Known::host_store`.
	option host_store_timeout = 15sec;

	## The set of all known addresses to store for preventing duplicate
	## logging of addresses.  It can also be used from other scripts to
	## inspect if an address has been seen in use.
	## Maintain the list of known hosts for 24 hours so that the existence
	## of each individual address is logged each day.
	##
	## In cluster operation, this set is distributed uniformly across
	## proxy nodes.
	global hosts: set[addr] &create_expire=1day &redef;

	## An event that can be handled to access the :zeek:type:`Known::HostsInfo`
	## record as it is sent on to the logging framework.
	global log_known_hosts: event(rec: HostsInfo);
}

event zeek_init()
	{
	if ( ! Known::use_host_store )
		return;

	Known::host_store = Cluster::create_store(Known::host_store_name);
	}

event Known::host_found(info: HostsInfo)
	{
	if ( ! Known::use_host_store )
		return;

	when [info] ( local r = Broker::put_unique(Known::host_store$store, info$host,
	                                    T, Known::host_store_expiry) )
		{
		if ( r$status == Broker::SUCCESS )
			{
			if ( r$result as bool )
				Log::write(Known::HOSTS_LOG, info);
			}
		else
			Reporter::error(fmt("%s: data store put_unique failure",
			                    Known::host_store_name));
		}
	timeout Known::host_store_timeout
		{
		# Can't really tell if master store ended up inserting a key.
		Log::write(Known::HOSTS_LOG, info);
		}
	}

event known_host_add(info: HostsInfo)
	{
	if ( use_host_store )
		return;

	if ( info$host in Known::hosts )
		return;

	add Known::hosts[info$host];

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::HOSTS_LOG, info);
	@endif
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( use_host_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	clear_table(Known::hosts);
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( use_host_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	clear_table(Known::hosts);
	}

event Known::host_found(info: HostsInfo)
	{
	if ( use_host_store )
		return;

	if ( info$host in Known::hosts )
		return;

	Cluster::publish_hrw(Cluster::proxy_pool, info$host, known_host_add, info);
	event known_host_add(info);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Known::HOSTS_LOG, [$columns=HostsInfo, $ev=log_known_hosts, $path="known_hosts", $policy=log_policy_hosts]);
	}

event connection_established(c: connection) &priority=5
	{
	if ( c$orig$state != TCP_ESTABLISHED )
		return;

	if ( c$resp$state != TCP_ESTABLISHED )
		return;

	local id = c$id;

	for ( host in set(id$orig_h, id$resp_h) )
		if ( addr_matches_host(host, host_tracking) )
			event Known::host_found([$ts = network_time(), $host = host]);
	}
