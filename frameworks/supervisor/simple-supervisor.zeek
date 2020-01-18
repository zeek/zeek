event zeek_init()
	{
	if ( Supervisor::is_supervisor() )
		{
		local sn = Supervisor::NodeConfig($name="foo", $interface="en0");
		local res = Supervisor::create(sn);

		if ( res == "" )
			print "supervisor created a new node";
		else
			print "supervisor failed to create node", res;
		}
	else
		print fmt("supervised node '%s' zeek_init()", Supervisor::node()$name);
	}

event zeek_done()
	{
	if ( Supervisor::is_supervised() )
		print fmt("supervised node '%s' zeek_done()", Supervisor::node()$name);
	else
		print "supervisor zeek_done()";
	}
