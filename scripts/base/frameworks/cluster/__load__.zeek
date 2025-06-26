# Load the core cluster support.
@load ./main
@load ./pools
@load ./telemetry

@if ( Cluster::is_enabled() )

# Give the node being started up it's peer name.
redef peer_description = Cluster::node;

@if ( Cluster::enable_round_robin_logging )
redef Broker::log_topic = Cluster::rr_log_topic;
@endif

# Add a cluster prefix.
@prefixes += cluster

# Broker-specific additions:
@if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER )
@load ./broker-backpressure
@load ./broker-telemetry
@endif

@if ( Supervisor::is_supervised() )
# When running a supervised cluster, populate Cluster::nodes from the node table
# the Supervisor provides to new Zeek nodes. The management framework configures
# the cluster this way.
@load ./supervisor
@if ( Cluster::Supervisor::__init_cluster_nodes() && Cluster::get_node_count(Cluster::LOGGER) > 0 )
redef Cluster::manager_is_logger = F;
@endif
@endif

@if ( |Cluster::nodes| == 0 )
# Fall back to loading a cluster topology from cluster-layout.zeek. If Zeek
# cannot find this script in your ZEEKPATH, it will exit. The script should only
# contain the cluster definition in the :zeek:id:`Cluster::nodes` variable.
# The zeekctl tool manages this file for you.
@load cluster-layout
@endif

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

@load ./broker-stores.zeek

@endif
@endif
