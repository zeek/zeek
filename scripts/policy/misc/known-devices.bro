##! This script provides infrastructure for logging devices for which Bro has
##! been able to determine the MAC address, and it logs them once per day (by
##! default).  The log that is output provides an easy way to determine a count
##! of the devices in use on a network per day.
##!
##! .. note::
##!
##!     This script will not generate any logs on its own, it needs to be
##!     supplied with information from elsewhere, such as
##!     :doc:`/scripts/policy/protocols/dhcp/known-devices-and-hostnames.bro`.

@load base/frameworks/cluster

module Known;

export {
	## The known-hosts logging stream identifier.
	redef enum Log::ID += { DEVICES_LOG };

	## The record type which contains the column fields of the known-devices
	## log.
	type DevicesInfo: record {
		## The timestamp at which the host was detected.
		ts:      time &log;
		## The MAC address that was detected.
		mac:     string &log;
	};

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Bro set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_device_store = T &redef;
	
	## Holds the set of all known devices.  Keys in the store are strings
	## representing MAC addresses and their associated value is always the
	## boolean value of "true".
	global device_store: Cluster::StoreInfo;

	## The Broker topic name to use for :bro:see:`Known::device_store`.
	const device_store_name = "bro/known/devices" &redef;

	## The expiry interval of new entries in :bro:see:`Known::device_store`.
	## This also changes the interval at which devices get logged.
	const device_store_expiry = 1day &redef;

	## The timeout interval to use for operations against
	## :bro:see:`Known::device_store`.
	const device_store_timeout = 15sec &redef;

	## The set of all known MAC addresses. It can accessed from other
	## scripts to add, and check for, addresses seen in use.
	##
	## We maintain each entry for 24 hours by default so that the existence
	## of individual addresses is logged each day.
	##
	## In cluster operation, this set is distributed uniformly across
	## proxy nodes.
	##
	## Use :bro:see:`Known::device_found` to update this set.
	global devices: set[string] &create_expire=1day &redef;

	## An event that can be handled to access the :bro:type:`Known::DevicesInfo`
	## record as it is sent on to the logging framework.
	global log_known_devices: event(rec: DevicesInfo);

	## Call this whenever a device is detected and the device database
	## will be updated and a log entry generated, if necessary.
	##
	## info: the device information to be logged
	global device_found: function(info: DevicesInfo);
}

event bro_init()
	{
	if ( ! Known::use_device_store )
		return;

	Known::device_store = Cluster::create_store(Known::device_store_name);
	}

event known_device_add(info: DevicesInfo)
	{
	if ( ! Known::use_device_store )
		return;

	when ( local r = Broker::put_unique(Known::device_store$store, info$mac,
	                                    T, Known::device_store_expiry) )
		{
		if ( r$status == Broker::SUCCESS )
			{
			if ( r$result as bool )
				Log::write(Known::DEVICES_LOG, info);
			}
		else
			Reporter::error(fmt("%s: data store put_unique failure",
			                    Known::device_store_name));
		}
	timeout Known::device_store_timeout
		{
		# Can't really tell if master store ended up inserting a key.
		Log::write(Known::DEVICES_LOG, info);
		}
	}

event known_device_add(info: DevicesInfo)
	{
	if ( Known::use_device_store )
		return;

	if ( info$mac in Known::devices )
		return;

	add Known::devices[info$mac];

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::DEVICES_LOG, info);
	@endif
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Known::use_device_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::devices = set();
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Known::use_device_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::devices = set();
	}

function device_found(info: DevicesInfo)
	{
	if ( ! Known::use_device_store )
		Cluster::publish_hrw(Cluster::proxy_pool, info$mac,
		                     known_device_add, info);

	event known_device_add(info);
	}

event bro_init()
	{
	Log::create_stream(Known::DEVICES_LOG, [$columns=DevicesInfo, $ev=log_known_devices, $path="known_devices"]);
	}
