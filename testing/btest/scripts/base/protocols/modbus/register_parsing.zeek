# @TEST-EXEC: zeek -r $TRACES/modbus/fuzz-1011.trace %INPUT >output
# @TEST-EXEC: btest-diff modbus.log
# @TEST-EXEC: btest-diff output

# modbus registers are 2-byte values.  Many messages send a variable amount
# of register values, with the quantity being derived from a byte count value
# that is also sent.  If the byte count value is invalid (e.g. an odd value
# might not be valid since registers must be 2-byte values), then the parser
# should not trigger any asserts, but generate a protocol_violation (in this
# case TCP_ApplicationAnalyzer::ProtocolViolation asserts its behavior for
# incomplete connections).

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
	{
	print "modbus_read_input_registers_request", c$id, headers, start_address, quantity;
	}

event modbus_read_input_registers_response(c: connection, headers: ModbusHeaders, registers: ModbusRegisters)
	{
	print "modbus_read_input_registers_response", c$id, headers, registers, |registers|;
	}
