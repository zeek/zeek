##! Establish ZeroMQ connectivity with the broker.

@load ./main
@load base/frameworks/cluster

module Cluster::Backend::ZeroMQ;

redef Cluster::enable_global_pub_sub = T;

event zeek_init() &priority=10
	{
	if ( run_proxy_thread )
		Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread();

	Cluster::init();
	}
