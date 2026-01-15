# @TEST-DOC: Tests the pcapng packet source, including sending events
#
# @TEST-EXEC: zeek -r $TRACES/pcapng-multi-interface.pcapng %INPUT > out
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn

export {
	redef record Conn::Info += {
		pcapng_interface: string &optional &log;
	};
}

event new_connection(c: connection) &priority=5 {
	c$conn$pcapng_interface = pcapng_current_interface_name();
}
