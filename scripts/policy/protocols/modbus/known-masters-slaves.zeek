##! Script for tracking known Modbus masters and slaves.
##!
##! .. todo:: This script needs a lot of work.  What might be more interesting
##!          is to track master/slave relationships based on commands sent and
##!          successful (non-exception) responses.

@load base/protocols/modbus

module Known;

export {
	redef enum Log::ID += { MODBUS_LOG };

	global log_policy_modbus: Log::PolicyHook;

	type ModbusDeviceType: enum {
		MODBUS_MASTER,
		MODBUS_SLAVE,
	};

	type ModbusInfo: record {
		## The time the device was discovered.
		ts:          time             &log;
		## The IP address of the host.
		host:        addr             &log;
		## The type of device being tracked.
		device_type: ModbusDeviceType &log;
	};

	## The Modbus nodes being tracked.
	global modbus_nodes: set[addr, ModbusDeviceType] &create_expire=1day &redef;

	## Event that can be handled to access the loggable record as it is sent
	## on to the logging framework.
	global log_known_modbus: event(rec: ModbusInfo);
}

event zeek_init() &priority=5
	{
	Log::create_stream(Known::MODBUS_LOG, [$columns=ModbusInfo, $ev=log_known_modbus, $path="known_modbus", $policy=log_policy_modbus]);
	}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	local master = c$id$orig_h;
	local slave  = c$id$resp_h;

	if ( [master, MODBUS_MASTER] !in modbus_nodes )
		{
		add modbus_nodes[master, MODBUS_MASTER];
		Log::write(MODBUS_LOG, [$ts=network_time(), $host=master, $device_type=MODBUS_MASTER]);
		}

	if ( [slave, MODBUS_SLAVE] !in modbus_nodes )
		{
		add modbus_nodes[slave, MODBUS_SLAVE];
		Log::write(MODBUS_LOG, [$ts=network_time(), $host=slave, $device_type=MODBUS_SLAVE]);
		}

	}
