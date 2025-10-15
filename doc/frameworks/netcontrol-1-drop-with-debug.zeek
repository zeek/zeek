event NetControl::init()
	{
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);
	}

event connection_established(c: connection)
	{
	NetControl::drop_connection(c$id, 20 secs);
	}
