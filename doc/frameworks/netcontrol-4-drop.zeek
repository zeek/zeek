function our_drop_connection(c: conn_id, t: interval)
	{
	# As a first step, create the NetControl::Entity that we want to block
	local e = NetControl::Entity($ty=NetControl::CONNECTION, $conn=c);
	# Then, use the entity to create the rule to drop the entity in the forward path
	local r = NetControl::Rule($ty=NetControl::DROP,
		$target=NetControl::FORWARD, $entity=e, $expire=t);

	# Add the rule
	local id = NetControl::add_rule(r);

	if ( id == "" )
		print "Error while dropping";
	}

event NetControl::init()
	{
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);
	}

event connection_established(c: connection)
	{
	our_drop_connection(c$id, 20 secs);
	}

