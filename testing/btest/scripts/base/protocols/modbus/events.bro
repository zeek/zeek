#
# @TEST-EXEC: bro -r $TRACES/modbus/modbus.trace %INPUT | sort | uniq -c | sed 's/^ *//g' >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat output | awk '{print $2}' | grep "^modbus_" | sort | uniq | wc -l >covered
# @TEST-EXEC: cat ${DIST}/src/event.bif  | grep "^event modbus_" | wc -l >total
# @TEST-EXEC: echo `cat covered` of `cat total` events triggered by trace >coverage
# @TEST-EXEC: btest-diff coverage

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    print "modbus_message", c, headers, is_orig;
}

event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
{
    print "modbus_exception", c, headers, code;
}

event modbus_read_coils_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    print "modbus_read_coils_request", c, headers, start_address, quantity;
}

event modbus_read_coils_response(c: connection, headers: ModbusHeaders, coils: ModbusCoils)
{
    print "modbus_read_coils_response", c, headers, coils;
}

event modbus_read_discrete_inputs_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    print "modbus_read_discrete_inputs_request", c, headers, start_address, quantity;
}

event modbus_read_discrete_inputs_response(c: connection, headers: ModbusHeaders, coils: ModbusCoils)
{
    print "modbus_read_discrete_inputs_response", c, headers, coils;
}

event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    print "modbus_read_holding_registers_request", c, headers, start_address, quantity;
}

event modbus_read_holding_registers_response(c: connection, headers: ModbusHeaders, byte_count: count, registers: ModbusRegisters)
{
    print "modbus_read_holding_registers_response", c, headers, registers;
}

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    print "modbus_read_input_registers_request", c, headers, start_address, quantity;
}

event modbus_read_input_registers_response(c: connection, headers: ModbusHeaders, byte_count: count, registers: ModbusRegisters)
{
    print "modbus_read_input_registers_response", c, headers, registers;
}

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, address: count, value: bool)
{
    print "modbus_write_single_coil_request", c, headers, address, value;
}

event modbus_write_single_coil_response(c: connection, headers: ModbusHeaders, address: count, value: bool)
{
    print "modbus_write_single_coil_response", c, headers, address, value;
}

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, address: count, value: count)
{
    print "modbus_write_single_register_request", c, headers, address, value;
}

event modbus_write_single_register_response(c: connection, headers: ModbusHeaders, address: count, value: count)
{
    print "modbus_write_single_register_response", c, headers, address, value;
}

event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders, start_address: count, coils: ModbusCoils)
{
    print "modbus_write_multiple_coils_request", c, headers, start_address, coils;
}

event modbus_write_multiple_coils_response(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    print "modbus_write_multiple_coils_response", c, headers, start_address, quantity;
}

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, start_address: count, byte_count: count, registers: ModbusRegisters)
{
    print "modbus_write_multiple_registers_request", c, headers, start_address, registers;
}

event modbus_write_multiple_registers_response(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    print "modbus_write_multiple_registers_response", c, headers, start_address, quantity;
}

event modbus_read_file_record_request(c: connection, headers: ModbusHeaders)
{
    print "modbus_read_file_record_request", c, headers;
}

event modbus_read_file_record_response(c: connection, headers: ModbusHeaders)
{
    print "modbus_read_file_record_response", c, headers;
}

event modbus_write_file_record_request(c: connection, headers: ModbusHeaders)
{
    print "modbus_write_file_record_request", c, headers;
}

event modbus_write_file_record_response(c: connection, headers: ModbusHeaders)
{
    print "modbus_write_file_record_response", c, headers;
}

event modbus_mask_write_register_request(c: connection, headers: ModbusHeaders, address: count, and_mask: count, or_mask: count)
{
    print "modbus_mask_write_register_request", c, headers, address, and_mask, or_mask;
}

event modbus_mask_write_register_response(c: connection, headers: ModbusHeaders, address: count, and_mask: count, or_mask: count)
{
    print "modbus_mask_write_register_response", c, headers, address, and_mask, or_mask;
}

event modbus_read_write_multiple_registers_request(c: connection, headers: ModbusHeaders, read_start_address: count, read_quantity: count, write_start_address: count, write_byte_count: count, write_registers: ModbusRegisters)
{
    print "modbus_read_write_multiple_registers_request", c, headers, read_start_address, read_quantity, write_start_address, write_registers;
}

event modbus_read_write_multiple_registers_response(c: connection, headers: ModbusHeaders, byte_count: count, written_registers: ModbusRegisters)
{
    print "modbus_read_write_multiple_registers_response", c, headers, written_registers;
}

event modbus_read_fifo_queue_request(c: connection, headers: ModbusHeaders, start_address: count)
{
    print "modbus_read_fifo_queue_request", c, headers, start_address;
}

event modbus_read_fifo_queue_response(c: connection, headers: ModbusHeaders, byte_count: count, fifos: ModbusRegisters)
{
    print "modbus_read_fifo_queue_response", c, headers, fifos;
}

