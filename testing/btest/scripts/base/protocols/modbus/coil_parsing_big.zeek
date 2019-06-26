#
# @TEST-EXEC: zeek -C -r $TRACES/modbus/modbusBig.pcap %INPUT | sort | uniq -c | sed 's/^ *//g' >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat output | awk '{print $2}' | grep "^modbus_" | sort | uniq | wc -l >covered
# @TEST-EXEC: cat ${DIST}/src/analyzer/protocol/modbus/events.bif  | grep "^event modbus_" | wc -l >total
# @TEST-EXEC: echo `cat covered` of `cat total` events triggered by trace >coverage
# @TEST-EXEC: btest-diff coverage

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    print "modbus_message", c$id, headers, is_orig;
}

event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
{
    print "modbus_exception", c$id, headers, code;
}

event modbus_read_coils_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    print "modbus_read_coils_request", c$id, headers, start_address, quantity;
}

event modbus_read_coils_response(c: connection, headers: ModbusHeaders, coils: ModbusCoils)
{
    print "modbus_read_coils_response", c$id, headers, coils;
}
event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, address: count, value: bool)
{
    print "modbus_write_single_coil_request", c$id, headers, address, value;
}

event modbus_write_single_coil_response(c: connection, headers: ModbusHeaders, address: count, value: bool)
{
    print "modbus_write_single_coil_response", c$id, headers, address, value;
}

event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders, start_address: count, coils: ModbusCoils)
{
    print "modbus_write_multiple_coils_request", c$id, headers, start_address, coils;
}

event modbus_write_multiple_coils_response(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    print "modbus_write_multiple_coils_response", c$id, headers, start_address, quantity;
}

