##! This script tracks the memory map of holding (read/write) registers and logs
##! changes as they are discovered.
##!
##! .. todo:: Not all register read and write functions are supported yet.

@load base/protocols/modbus
@load base/utils/directions-and-hosts

module Modbus;

export {
	redef enum Log::ID += { Modbus::REGISTER_CHANGE_LOG };

	global log_policy_register_change: Log::PolicyHook;

	## The hosts that should have memory mapping enabled.
	option track_memmap: Host = ALL_HOSTS;

	type MemmapInfo: record {
		## Timestamp for the detected register change.
		ts:        time     &log;
		## Unique ID for the connection.
		uid:       string   &log;
		## Connection ID.
		id:        conn_id  &log;
		## The device memory offset.
		register:  count    &log;
		## The old value stored in the register.
		old_val:   count    &log;
		## The new value stored in the register.
		new_val:   count    &log;
		## The time delta between when the *old_val* and *new_val* were
		## seen.
		delta:     interval &log;
	};

	type RegisterValue: record {
		last_set: time;
		value:    count;
	};

	## Indexed on the device register value and yielding the register value.
	type Registers: table[count] of RegisterValue;

	## The memory map of slaves is tracked with this variable.
	global device_registers: table[addr] of Registers;

	## This event is generated every time a register is seen to be different
	## than it was previously seen to be.
	global changed_register: event(c: connection, register: count, old_val: count, new_val: count, delta: interval);
}

redef record Modbus::Info += {
	track_address: count &default=0;
};

event zeek_init() &priority=5
	{
	Log::create_stream(Modbus::REGISTER_CHANGE_LOG, [$columns=MemmapInfo, $path="modbus_register_change", $policy=log_policy_register_change]);
	}

event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
	{
	c$modbus$track_address = start_address+1;
	}

event modbus_read_holding_registers_response(c: connection, headers: ModbusHeaders, registers: ModbusRegisters)
	{
	local slave = c$id$resp_h;

	if ( ! addr_matches_host(slave, track_memmap ) )
		return;

	if ( slave !in device_registers )
		device_registers[slave] = table();

	local slave_regs = device_registers[slave];
	for ( i in registers )
		{
		if ( c$modbus$track_address in slave_regs )
			{
			if ( slave_regs[c$modbus$track_address]$value != registers[i] )
				{
				local delta = network_time() - slave_regs[c$modbus$track_address]$last_set;
				event Modbus::changed_register(c, c$modbus$track_address,
				                               slave_regs[c$modbus$track_address]$value, registers[i],
				                               delta);

				slave_regs[c$modbus$track_address]$last_set = network_time();
				slave_regs[c$modbus$track_address]$value = registers[i];
				}
			}
		else
			{
			local tmp_reg: RegisterValue = [$last_set=network_time(), $value=registers[i]];
			slave_regs[c$modbus$track_address] = tmp_reg;
			}

		++c$modbus$track_address;
		}
	}

event Modbus::changed_register(c: connection, register: count, old_val: count, new_val: count, delta: interval)
	{
	local rec: MemmapInfo = [$ts=network_time(), $uid=c$uid, $id=c$id,
	                         $register=register, $old_val=old_val, $new_val=new_val, $delta=delta];
	Log::write(REGISTER_CHANGE_LOG, rec);
	}
