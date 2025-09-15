event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

event connection_established(c: connection)
	{
	if ( |NetControl::find_rules_addr(c$id$orig_h)| > 0 )
		{
		print "Rule already exists";
		return;
		}

	NetControl::drop_connection(c$id, 20 secs);
	print "Rule added";
	}
