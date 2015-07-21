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
	BrokerComm::subscribe_to_events("/bro/event/cluster/control/request");
	for ( e in Control::controllee_events )
		BrokerComm::auto_event("/bro/event/cluster/control/response", lookup_ID(e));

	# Manager settings
	if(Cluster::local_node_type() ==  Cluster::MANAGER )
		{
		#print "local node is a manager";
		BrokerComm::subscribe_to_events("/bro/event/cluster/manager/response");

		# Need to publish: manager2worker_events, manager2proxy_events
		for (e in Cluster::manager2worker_events )
			BrokerComm::auto_event("/bro/event/cluster/worker/request", lookup_ID(e));

		BrokerComm::auto_event("/bro/event/cluster/worker/request", Cluster::test_worker_event);
		BrokerComm::auto_event("/bro/event/cluster/proxy/request", Cluster::test_proxy_event);
		
		for (e in Cluster::manager2proxy_events )
			BrokerComm::auto_event("/bro/event/cluster/proxy/request", lookup_ID(e));
		}

	# Proxy settings
	else if( Cluster::local_node_type() == Cluster::PROXY )
		{
		#print "local node is a proxy";
		BrokerComm::subscribe_to_events("/bro/event/cluster/proxy/request");

		# Need to publish: proxy2manager_events, proxy2worker_events
		for ( e in Cluster::proxy2manager_events )
			BrokerComm::auto_event("/bro/event/cluster/manager/response", lookup_ID(e));

		BrokerComm::auto_event("/bro/event/cluster/manager/response", Cluster::test_proxy_response);

		for ( e in Cluster::proxy2worker_events )
			BrokerComm::auto_event("/bro/event/cluster/worker/response", lookup_ID(e));
		}

	# Worker settings
	else if( Cluster::local_node_type() == Cluster::WORKER )
		{
		#print "local node is a worker";
		BrokerComm::subscribe_to_events("/bro/event/cluster/worker/request");

		# Need to publish: worker2manager_events, worker2proxy_events
		for ( e in Cluster::worker2manager_events )
			BrokerComm::auto_event("/bro/event/cluster/manager/response", lookup_ID(e));
		
		BrokerComm::auto_event("/bro/event/cluster/manager/response", Cluster::test_worker_response);
		
		for ( e in Cluster::worker2proxy_events )
			BrokerComm::auto_event("/bro/event/cluster/proxy/response", lookup_ID(e));
		}
	}
