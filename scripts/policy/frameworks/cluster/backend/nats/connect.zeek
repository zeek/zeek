##! Establish NATS connectivity

@load ./main

module Cluster::Backend::NATS;

event zeek_init() &priority=-10
	{
	Cluster::init();
	}

event zeek_done() &priority=-100
	{
	# Upon shutdown, send out a goodbye so other nodes can properly
	# raise Cluster::node_down().
	Cluster::publish(discovery_topic, Cluster::Backend::NATS::goodbye, Cluster::node, Cluster::node_id());
	}


