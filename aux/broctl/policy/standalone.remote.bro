# $Id: standalone.remote.bro 6860 2009-08-14 19:01:47Z robin $
#
# We only need to accept update connections from the shell.
# 

@load broctl

event bro_init() 
{
	# Connections from the manager for configuration updates.
	Remote::destinations["update"] 
		=  [$host = BroCtl::manager$ip, $p=BroCtl::manager$p, $sync=F, $events=BroCtl::update_events, $class="update"];

	# Configure Time Machine.
	if ( BroCtl::tm_host != 0.0.0.0 )
		Remote::destinations["time-machine"] = [$host=BroCtl::tm_host, $p=BroCtl::tm_port, $connect=T, $retry=1min];
}


