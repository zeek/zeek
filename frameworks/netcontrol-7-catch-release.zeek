event NetControl::init()
	{
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);
	}

event connection_established(c: connection)
	{
	NetControl::drop_address_catch_release(c$id$orig_h);
	}
