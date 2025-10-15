event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	Broker::listen("127.0.0.1", 9999/tcp);

	local cluster: table[string] of Supervisor::ClusterEndpoint;
	cluster["manager"] = [$role=Supervisor::MANAGER, $host=127.0.0.1, $p=10000/tcp];
	cluster["logger"] = [$role=Supervisor::LOGGER, $host=127.0.0.1, $p=10001/tcp];
	cluster["proxy"] = [$role=Supervisor::PROXY, $host=127.0.0.1, $p=10002/tcp];
	cluster["worker"] = [$role=Supervisor::WORKER, $host=127.0.0.1, $p=10003/tcp, $interface="en0"];

	for ( n, ep in cluster )
		{
		local sn = Supervisor::NodeConfig($name=n);
		sn$cluster = cluster;
		sn$directory = n;

		if ( ep?$interface )
			sn$interface = ep$interface;

		local res = Supervisor::create(sn);

		if ( res != "" )
			print fmt("supervisor failed to create node '%s': %s", n, res);
		}
	}
