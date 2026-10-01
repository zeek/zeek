# @TEST-DOC: Test the limitation devices and slaves in the modbus/track-memmap policy
#
# @TEST-EXEC: zeek -b -r $TRACES/modbus/track-memmap-memory-exhaustion.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/modbus
@load policy/protocols/modbus/track-memmap
@load base/frameworks/notice/weird

redef Modbus::max_device_registers=10;
redef Modbus::max_slave_registers=5;
