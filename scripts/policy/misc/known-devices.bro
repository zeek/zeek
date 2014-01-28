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

	## The set of all known MAC addresses. It can accessed from other
	## scripts to add, and check for, addresses seen in use.
	##
	## We maintain each entry for 24 hours by default so that the existence
	## of individual addresses is logged each day.
	global known_devices: set[string] &create_expire=1day &synchronized &redef;

	## An event that can be handled to access the :bro:type:`Known::DevicesInfo`
	## record as it is sent on to the logging framework.
	global log_known_devices: event(rec: DevicesInfo);
}

event bro_init()
	{
	Log::create_stream(Known::DEVICES_LOG, [$columns=DevicesInfo, $ev=log_known_devices]);
	}
