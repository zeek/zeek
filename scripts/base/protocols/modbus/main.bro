##! Base Modbus analysis script.

module Modbus;

export {

}

# Configure DPD and the packet filter.
redef capture_filters += { ["modbus"] = "tcp port 502" };
redef dpd_config += { [ANALYZER_MODBUS] = [$ports = set(502/tcp)] };
redef likely_server_ports += { 502/tcp };


event modbus_exception(c: connection, header: ModbusHeaders, code: count)
	{
	print fmt("%.6f %s There was an exception: %s", network_time(), c$id, exception_codes[code]);
	}

event modbus_message(c: connection, header: ModbusHeaders, is_orig: bool)
	{
	#if ( function_codes[header$function_code] in set("READ_MULTIPLE_REGISTERS", "READ_WRITE_REGISTERS", "WRITE_MULTIPLE_REGISTERS") )
	#	return; 

	print fmt("%.6f %s %s: %s", network_time(), c$id, is_orig ? "request":"response", function_codes[header$function_code]);
	}
