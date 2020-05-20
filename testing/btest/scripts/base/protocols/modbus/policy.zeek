#
# @TEST-EXEC: zeek -r $TRACES/modbus/modbus.trace %INPUT
# @TEST-EXEC: btest-diff modbus.log
# @TEST-EXEC: btest-diff modbus_register_change.log
# @TEST-EXEC: btest-diff known_modbus.log
#

@load protocols/modbus/known-masters-slaves
@load protocols/modbus/track-memmap

redef DPD::ignore_violations_after = 1;
