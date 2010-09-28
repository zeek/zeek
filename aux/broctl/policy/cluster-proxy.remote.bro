# $Id: cluster-proxy.remote.bro 6811 2009-07-06 20:41:10Z robin $

event bro_init() 
	{
	# Set up worker connections.
	for ( n in BroCtl::workers ) 
		# We set up Bro to accept connection from all nodes, even those which 
		# won't connect to us. It's easier this way. :-)
		Remote::destinations[fmt("w%d", n)]
 			= [$host=BroCtl::workers[n]$ip, $connect=F, $sync=T, $auth=T, $class="proxy"];

	# Set up proxy connections. Each proxy connects to the next in line, and 
	# accepts connections from the previous one. 
	# (This is not ideal for setups with many proxies but we will quite 
	# unlikely have those.)
	# FIXME: Once we're using multiple proxies, we should also figure out some $class scheme ...

	if ( PROXY > 1 )
		Remote::destinations[fmt("p%d", PROXY-1)]
			= [$host=BroCtl::proxies[PROXY-1]$ip, $p=BroCtl::proxies[PROXY-1]$p, $connect=F, $auth=T, $sync=T];

	if ( PROXY < |BroCtl::proxies| )
		Remote::destinations[fmt("p%d", PROXY+1)]
			= [$host=BroCtl::proxies[PROXY+1]$ip, $p=BroCtl::proxies[PROXY+1]$p, $connect=T, $auth=F, $sync=T, $retry=1mins];

	# Finally the manager, to send it status updates.
	Remote::destinations["manager"] = 
		[$host=BroCtl::manager$ip, $p=BroCtl::manager$p, $connect=T, $sync=F, $retry=1mins, $class=BroCtl::proxies[PROXY]$tag];

	# Connections from the manager for configuration updates.
	Remote::destinations["update"] 
		=  [$host = BroCtl::manager$ip, $p=BroCtl::manager$p, $sync=F, $events=BroCtl::update_events, $class="update"];
	}
