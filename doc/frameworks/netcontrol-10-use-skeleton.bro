event NetControl::init()
	{
	local skeleton_plugin = NetControl::create_skeleton("");
	NetControl::activate(skeleton_plugin, 0);
	}

event connection_established(c: connection)
	{
	NetControl::drop_connection(c$id, 20 secs);
	}
