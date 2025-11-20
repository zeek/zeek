# Helper scripts for test expecting XPUB/XSUB ports allocated by
# btest and configuring the ZeroMQ globals.
@load base/utils/numbers
@load base/utils/addrs

@load frameworks/cluster/backend/zeromq

# Use 127.0.0.1 by default for testing, unless there's a cluster-layout with
# a manager. In that case, use its IP address.
const local_addr_str = "127.0.0.1" &redef;
@if ( "manager" in Cluster::nodes )
redef local_addr_str = addr_to_uri(Cluster::nodes["manager"]$ip);
@endif

redef Cluster::Backend::ZeroMQ::listen_xpub_endpoint = fmt("tcp://%s:%s", local_addr_str, port_to_count(to_port(getenv("XPUB_PORT"))));
redef Cluster::Backend::ZeroMQ::listen_xsub_endpoint = fmt("tcp://%s:%s", local_addr_str, port_to_count(to_port(getenv("XSUB_PORT"))));
redef Cluster::Backend::ZeroMQ::connect_xpub_endpoint = fmt("tcp://%s:%s", local_addr_str, port_to_count(to_port(getenv("XSUB_PORT"))));
redef Cluster::Backend::ZeroMQ::connect_xsub_endpoint = fmt("tcp://%s:%s", local_addr_str, port_to_count(to_port(getenv("XPUB_PORT"))));
