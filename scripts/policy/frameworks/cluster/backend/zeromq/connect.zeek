##! Establish ZeroMQ connectivity with the broker.

module Cluster::Backend::ZeroMQ;

event zeek_init()
	{
	if ( run_broker_thread )
		Cluster::Backend::ZeroMQ::spawn_broker_thread();

	# Connect to the broker thread (connect_xpub_endpoint
	# and connect_xsub_endpoint) and the logger endpoints
	# via connect_log_endpoints. Also starts listening on
	# logging pull sockets if configured.
	Cluster::Backend::ZeroMQ::connect();

	# Get things going by subscribing to our own topic.
	Cluster::subscribe(Cluster::nodeid_topic(Cluster::node_id()));
	}
