##! Establish ZeroMQ connectivity with the broker.

@load ./main

module Cluster::Backend::ZeroMQ;


event zeek_init() &priority=10
	{
	if ( run_proxy_thread )
		{
		if ( ! Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread() )
			Reporter::fatal("Failed to spawn ZeroMQ proxy thread");
		}

	if ( ! Cluster::init() )
		Reporter::fatal("Failed initialize ZeroMQ backend");
	}
