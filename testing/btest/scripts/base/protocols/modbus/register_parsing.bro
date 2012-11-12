# @TEST-EXEC: bro -r $TRACES/modbus/fuzz-1011.trace %INPUT >output
# @TEST-EXEC: btest-diff modbus.log
# @TEST-EXEC: btest-diff output

# modbus registers are 2-byte values.  Many messages send a variable amount
# of register values, with the quantity being derived from a byte count value
# that is also sent.  If the byte count value is invalid (e.g. an odd value
# might not be valid since registers must be 2-byte values), then the parser
# should not trigger any asserts, but the resulting event could indicate
# the strangeness (i.e. byte_count != 2*|registers|).

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
	{
	print "modbus_read_input_registers_request", c$id, headers, start_address, quantity;
	}

event modbus_read_input_registers_response(c: connection, headers: ModbusHeaders, byte_count: count, registers: ModbusRegisters)
	{
	print "modbus_read_input_registers_response", c$id, headers, registers, |registers|, byte_count;
	}
