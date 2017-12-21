# Load the core cluster support.
@load ./main
@load ./pools

@if ( Cluster::is_enabled() )

# Give the node being started up it's peer name.
redef peer_description = Cluster::node;

@if ( Cluster::enable_round_robin_logging )
redef Broker::log_topic = Cluster::rr_log_topic;
@endif

# Add a cluster prefix.
@prefixes += cluster

# If this script isn't found anywhere, the cluster bombs out.
# Loading the cluster framework requires that a script by this name exists
# somewhere in the BROPATH.  The only thing in the file should be the
# cluster definition in the :bro:id:`Cluster::nodes` variable.
@load cluster-layout

@if ( Cluster::node in Cluster::nodes )

@load ./setup-connections

@if ( Cluster::local_node_type() == Cluster::MANAGER )
@load ./nodes/manager
# If no logger is defined, then the manager receives logs.
@if ( Cluster::manager_is_logger )
@load ./nodes/logger
@endif
@endif

@if ( Cluster::local_node_type() == Cluster::LOGGER )
@load ./nodes/logger
@endif

@if ( Cluster::local_node_type() == Cluster::PROXY )
@load ./nodes/proxy
@endif

@if ( Cluster::local_node_type() == Cluster::WORKER )
@load ./nodes/worker
@endif

@endif
@endif
