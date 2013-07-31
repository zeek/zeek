##! This script logs devices for which Bro has been able to determine the MAC
##! address and logs the MAC address once per day (by default). The log that 
##! is output provides an easy way to determine a count of the devices in use
##! on a network per day.

##! NOTE: This script will not generate any logs. Scripts such as
##! policy/protocols/dhcp/known-devices-and-hostnames are needed.
module Known;

export {
	## The known-hosts logging stream identifier.
	redef enum Log::ID += { DEVICES_LOG };

	## The record type which contains the column fields of the known-devices log.
	type DevicesInfo: record {
		## The timestamp at which the host was detected.
		ts:      time &log;
		## The MAC address that was detected.
		mac:     string &log;
	};
	
	## The set of all known MAC addresses to store for preventing duplicate 
	## logging of addresses.  It can also be used from other scripts to 
	## inspect if an address has been seen in use.
	## Maintain the list of known devices for 24 hours so that the existence
	## of each individual address is logged each day.
	global known_devices: set[string] &create_expire=1day &synchronized &redef;

	## An event that can be handled to access the :bro:type:`Known::DevicesInfo`
	## record as it is sent on to the logging framework.
	global log_known_devices: event(rec: DevicesInfo);
}

event bro_init()
	{
	Log::create_stream(Known::DEVICES_LOG, [$columns=DevicesInfo, $ev=log_known_devices]);
	}
