# Helper script expecting XPUB_PORT / XSUB_PORT environments
# and redefining the ZeroMQ options accordingly and starting
# the zmq_proxy_thread.
#
# This is primarily useful for testing of WebSocket functionality
# while the ZeroMQ backend is enabled.
@load base/utils/numbers

@load frameworks/cluster/backend/zeromq

const local_addr_str = "127.0.0.1" &redef;
redef Cluster::Backend::ZeroMQ::listen_xpub_endpoint = fmt("tcp://%s:%s", local_addr_str, port_to_count(to_port(getenv("XPUB_PORT"))));
redef Cluster::Backend::ZeroMQ::listen_xsub_endpoint = fmt("tcp://%s:%s", local_addr_str, port_to_count(to_port(getenv("XSUB_PORT"))));
redef Cluster::Backend::ZeroMQ::connect_xpub_endpoint = fmt("tcp://%s:%s", local_addr_str, port_to_count(to_port(getenv("XSUB_PORT"))));
redef Cluster::Backend::ZeroMQ::connect_xsub_endpoint = fmt("tcp://%s:%s", local_addr_str, port_to_count(to_port(getenv("XPUB_PORT"))));

event zeek_init() &priority=100
	{
	if ( ! Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread() )
		Reporter::fatal("Failed to spawn ZeroMQ proxy thread");

	if ( ! Cluster::init() )
		Reporter::fatal("Failed to initialize ZeroMQ backend");
	}
