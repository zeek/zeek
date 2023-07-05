##! This script adds link-layer address (MAC) information to the modbus logs

@load base/protocols/modbus

module Modbus;

redef record Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the Modbus::Info structure.
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	if ( c$orig?$l2_addr )
		c$modbus$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$modbus$resp_l2_addr = c$resp$l2_addr;
	}
