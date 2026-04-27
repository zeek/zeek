##! This script logs hosts that Zeek determines have performed complete TCP
##! handshakes and logs the address once per day (by default).  The log that
##! is output provides an easy way to determine a count of the IP addresses in
##! use on a network per day.

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

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

	## Use the storage framework to enable persistence of the stored
	## hosts between runs.
	const enable_hosts_persistence = F &redef;

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Zeek set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_host_store = F &redef &deprecated="Remove in v9.1. Store support has been disabled by default since Zeek 6.0 due to performance and will be removed.";

	## The hosts whose existence should be logged and tracked.
	## See :zeek:type:`Host` for possible choices.
	option host_tracking = LOCAL_HOSTS;

	## Holds the set of all known hosts.  Keys in the store are addresses
	## and their associated value will always be the "true" boolean.
	global host_broker_store: Cluster::StoreInfo;

	## The Broker topic name to use for :zeek:see:`Known::host_broker_store`.
	const host_store_name = "zeek/known/hosts" &redef;

	## This requires setting a configuration in local.zeek that sets the
	## Known::enable_hosts_persistence boolean to T, and optionally setting different
	## values in the Known::host_store_backend_options record.

	## Backend to use for storing known hosts data using the storage framework.
	global host_store_backend: opaque of Storage::BackendHandle;

	## The name to use for :zeek:see:`Known::host_store_backend`. This will be used
	## by the backends to differentiate tables/keys. This should be alphanumeric so
	## that it can be used as the table name for the storage framework.
	const host_store_prefix = "zeekknownhosts" &redef;

	## The type of storage backend to open.
	const host_store_backend_type : Storage::Backend = Storage::STORAGE_BACKEND_SQLITE &redef;

	## The options for the host store. This should be redef'd in local.zeek to set
	## connection information for the backend. The options default to a memory store.
	const host_store_backend_options : Storage::BackendOptions = [ $sqlite = [
		$database_path=fmt("%s/known/hosts.sqlite", Cluster::default_store_dir),
		$table_name=Known::host_store_name ]] &redef;

	## The expiry interval of new entries in :zeek:see:`Known::host_broker_store` and
	## :zeek:see:`Known::host_store_backend`. This also changes the interval at
	## which hosts get logged.
	const host_store_expiry = 1day &redef;

	## The timeout interval to use for operations against
	## :zeek:see:`Known::host_broker_store` and :zeek:see:`Known::host_store_backend`.
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
@pragma push ignore-deprecations
	if ( ! Known::use_host_store && ! Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

@pragma push ignore-deprecations
	if ( Known::use_host_store )
		{
		Known::host_broker_store = Cluster::create_store(Known::host_store_name);
@pragma pop ignore-deprecations
		}
	else
		{
		local res = Storage::Sync::open_backend(Known::host_store_backend_type, Known::host_store_backend_options, addr, bool);
		if ( res$code == Storage::SUCCESS )
			Known::host_store_backend = res$value;
		else
			Reporter::error(fmt("%s: Failed to open backend connection: %s", Known::host_store_prefix, res$error_str));
		}
	}

event Known::host_found(info: HostsInfo)
	{
@pragma push ignore-deprecations
	if ( ! Known::use_host_store && ! Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

@pragma push ignore-deprecations
	if ( Known::use_host_store )
		{
@pragma pop ignore-deprecations
		when [info] ( local r = Broker::put_unique(Known::host_broker_store$store, info$host,
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
	else
		{
		when [info] ( local put_res = Storage::Async::put(Known::host_store_backend, [$key=info$host, $value=T, $overwrite=F,
		                                                    $expire_time=Known::host_store_expiry]) )
			{
			if ( put_res$code == Storage::SUCCESS )
				Log::write(Known::HOSTS_LOG, info);
			else if ( put_res$code != Storage::KEY_EXISTS )
				Reporter::error(fmt("%s: data store put_unique failure: %s",
				                    Known::host_store_name, put_res$error_str));
			}
		timeout Known::host_store_timeout
			{
			Log::write(Known::HOSTS_LOG, info);
			}
		}
	}

event known_host_add(info: HostsInfo)
	{
@pragma push ignore-deprecations
	if ( use_host_store || Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

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
@pragma push ignore-deprecations
	if ( use_host_store || Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	clear_table(Known::hosts);
	}

event Cluster::node_down(name: string, id: string)
	{
@pragma push ignore-deprecations
	if ( use_host_store || Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	clear_table(Known::hosts);
	}

event Known::host_found(info: HostsInfo)
	{
@pragma push ignore-deprecations
	if ( use_host_store || Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

	if ( info$host in Known::hosts )
		return;

	Cluster::publish_hrw(Cluster::proxy_pool, info$host, known_host_add, info);
	event known_host_add(info);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Known::HOSTS_LOG, Log::Stream($columns=HostsInfo, $ev=log_known_hosts, $path="known_hosts", $policy=log_policy_hosts));
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
			event Known::host_found(Known::HostsInfo($ts = network_time(), $host = host));
	}
