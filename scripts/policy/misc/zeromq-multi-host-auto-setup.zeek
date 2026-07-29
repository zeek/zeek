##! This script interrogates the Cluster::nodes content to configure
##! the XPUB/XSUB connect and listen endpoints by assuming that the
##! manager node runs the XPUB/XSUB proxy thread using ports 5555 and 5556.
##! Ports are configurable via ZEEK_CLUSTER_BACKEND_ZEROMQ_XPUB_PORT
##! and ZEEK_CLUSTER_BACKEND_ZEROMQ_XSUB_PORT environment variables.
##!
##! If you do not run the XPUB/XSUB proxy in the manager node, this script
##! is not useful and you'll need to whip up your own.

@load frameworks/cluster/backend/zeromq

module Cluster::Backend::ZeroMQ;

# redef variables are a bad fit for doing things at parse time. Use
# env variables which feels more devopsy anyhow.
# split_string1 on / to support bare 4711 and 4711/tcp style ports,
# just in case.
const env_xpub_port = getenv("ZEEK_CLUSTER_BACKEND_ZEROMQ_XPUB_PORT");
@if ( |env_xpub_port| > 0)
const xpub_port = fmt("%s/tcp", split_string1(env_xpub_port, /\//)[0]) as port;
@else
const xpub_port = 5555/tcp;
@endif

const env_xsub_port = getenv("ZEEK_CLUSTER_BACKEND_ZEROMQ_XSUB_PORT");
@if ( |env_xsub_port| > 0)
const xsub_port = fmt("%s/tcp", split_string1(env_xsub_port, /\//)[0]) as port;
@else
const xsub_port = 5556/tcp;
@endif

# Guard for when this script is loaded without clustering enabled (mostly tests)
@if ( "manager" in Cluster::nodes && Cluster::node in Cluster::nodes )
const my_addr = Cluster::nodes[Cluster::node]$ip;
const manager_addr = Cluster::nodes["manager"]$ip;
const manager_addr_uri = addr_to_uri(manager_addr);
@else
const my_addr = [::1];
const manager_addr = [::1];
const manager_addr_uri = addr_to_uri(manager_addr);
@endif

# Configure the listening endpoints for the XPUB/XSUB socket on the manager.
@if ( Cluster::local_node_type() == Cluster::MANAGER )
redef listen_xpub_endpoint = fmt("tcp://%s:%s", manager_addr_uri, xpub_port as count);
redef listen_xsub_endpoint = fmt("tcp://%s:%s", manager_addr_uri, xsub_port as count);
@else
redef listen_xpub_endpoint = "";
redef listen_xsub_endpoint = "";
@endif

# Configure all other nodes to connect to the manager via TCP.
redef connect_xpub_endpoint = fmt("tcp://%s:%s", manager_addr_uri, xsub_port as count);
redef connect_xsub_endpoint = fmt("tcp://%s:%s", manager_addr_uri, xpub_port as count);

redef ipv6 = is_v6_addr(manager_addr) || is_v6_addr(my_addr);
