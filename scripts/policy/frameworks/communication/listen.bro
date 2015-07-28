##! Loading this script will make the Bro instance listen for remote 
##! Bro instances to connect.

@load base/frameworks/communication
@load base/frameworks/broker

module Communication;

event bro_init() &priority=-10
	{
	print "broker listens on", fmt("%s:%s", listen_interface, listen_port);
	BrokerComm::listen(listen_port, fmt("%s", listen_interface));
	
	# All nodes need to subscribe to control-related events
	BrokerComm::subscribe_to_events(fmt("%s/control/request", Cluster::pub_sub_prefix));
	for ( e in Control::controllee_events )
		BrokerComm::auto_event(fmt("%s/control/response", Cluster::pub_sub_prefix), lookup_ID(e));
	}
