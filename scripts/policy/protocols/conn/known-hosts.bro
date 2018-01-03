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
	##
	## In cluster operation, this set is distributed uniformly across
	## proxy nodes.
	global hosts: set[addr] &create_expire=1day &redef;

	## An event that can be handled to access the :bro:type:`Known::HostsInfo`
	## record as it is sent on to the logging framework.
	global log_known_hosts: event(rec: HostsInfo);
}

event known_host_add(info: HostsInfo)
	{
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
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::hosts = set();
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::hosts = set();
	}

function host_found(info: HostsInfo)
	{
	Cluster::publish_hrw(Cluster::proxy_pool, info$host, known_host_add, info);
	event known_host_add(info);
	}

event bro_init()
	{
	Log::create_stream(Known::HOSTS_LOG, [$columns=HostsInfo, $ev=log_known_hosts, $path="known_hosts"]);
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
			Known::host_found([$ts = network_time(), $host = host]);
	}
