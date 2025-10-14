hook NetControl::rule_policy(r: NetControl::Rule)
	{
	if ( r$ty == NetControl::DROP &&
	     r$entity$ty == NetControl::CONNECTION &&
			 r$entity$conn$orig_h in 192.168.0.0/16 )
			 {
			 print "Ignored connection from", r$entity$conn$orig_h;
			 break;
			 }
	}

event NetControl::init()
	{
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);
	}

event connection_established(c: connection)
	{
	NetControl::drop_connection(c$id, 20 secs);
	}

