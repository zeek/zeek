##! Establish NATS connectivity

module Cluster::Backend::NATS;

event zeek_init()
	{
	Cluster::Backend::NATS::connect();
	}

event zeek_done() &priority=-100
	{
	# Upon shutdown, send out a goodbye so other nodes can properly
	# raise Cluster::node_down().
	Cluster::publish(discovery_topic, Cluster::Backend::NATS::goodbye, Cluster::node, Cluster::node_id());
	}


