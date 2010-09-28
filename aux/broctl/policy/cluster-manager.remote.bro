# $Id: cluster-manager.remote.bro 6860 2009-08-14 19:01:47Z robin $
#
# This is the MANAGER remote configuration.
#
# The manager is passive (the workers connect to us), and once connected
# the manager registers for the events on the workers that are needed
# to get the desired data from the workers.

@load broctl

const cluster_events = /.*(print_hook|notice_action|TimeMachine::command|Drop::).*/;

event bro_init() 
{
	# Set up remote dests for WORKERS based on central cluster config.
	for ( n in BroCtl::workers ) 
		Remote::destinations[fmt("w%d", n)]
			= [$host=BroCtl::workers[n]$ip, $connect=F, $sync=F, $class=BroCtl::workers[n]$tag, $events=cluster_events];

	# Set up remote dests for PROXIES, just to get ResourceStats.
	for ( n in BroCtl::proxies ) 
		Remote::destinations[fmt("p%d", n)]
			= [$host=BroCtl::proxies[n]$ip, $connect=F, $sync=F, $class=BroCtl::proxies[n]$tag, $events=/.*(notice_action).*/ ];

	# Connections from the manager for configuration updates.
	Remote::destinations["update"] 
		=  [$host = BroCtl::manager$ip, $p=BroCtl::manager$p, $sync=F, $events=BroCtl::update_events, $class="update"];

	# Configure Time Machine.
	if ( BroCtl::tm_host != 0.0.0.0 )
		Remote::destinations["time-machine"] = [$host=BroCtl::tm_host, $p=BroCtl::tm_port, $connect=T, $retry=1min];
}


