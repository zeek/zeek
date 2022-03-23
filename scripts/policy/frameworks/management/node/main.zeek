##! This module provides Management framework functionality that needs to be
##! present in every cluster node to allow Management agents to interact with
##! the cluster nodes they manage.

@load policy/frameworks/management/agent/config
@load policy/frameworks/management/log

@load ./config

module Management::Node;

# Tag our logs correctly
redef Management::Log::role = Management::NODE;

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	local epi = Management::Agent::endpoint_info();

	# If this is the agent peering, notify it that we're ready
	if ( peer$network$address == epi$network$address &&
	     peer$network$bound_port == epi$network$bound_port )
		event Management::Node::API::notify_node_hello(Cluster::node);
	}

event zeek_init()
	{
	local epi = Management::Agent::endpoint_info();

	Broker::peer(epi$network$address, epi$network$bound_port, Management::connect_retry);
	Broker::subscribe(node_topic);

	# Events automatically sent to the Management agent.
	local events: vector of any = [
	    Management::Node::API::notify_node_hello
	    ];

	for ( i in events )
		Broker::auto_publish(node_topic, events[i]);
	}
