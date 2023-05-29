# Load the core cluster support.
@load ./main
@load ./pools


# If cluster-layout.zeek isn't found anywhere, the cluster bombs out.
# Loading the cluster framework requires that a script by this name exists
# somewhere in the ZEEKPATH.  The only thing in the file should be the
# cluster definition in the :zeek:id:`Cluster::nodes` variable.
#
# We can not use if &analyze here, because the &analyze part will try to
# load the @load cluster-layout and that might not exist.
@if ( Cluster::is_enabled() )
@if ( ! Supervisor::__init_cluster() )
# When running a supervised cluster, Cluster::nodes is instead populated
# from the internal C++-layer directly via the above BIF.
@load cluster-layout
@endif
@endif

# This needs to be @if &analyze because subsequent
# @if's in per-node directories use it.
@if ( Cluster::is_enabled() ) &analyze

# Give the node being started up it's peer name.
redef peer_description = Cluster::node;

@if ( Cluster::enable_round_robin_logging ) &analyze
redef Broker::log_topic = Cluster::rr_log_topic;
@endif

# Add a cluster prefix.
@prefixes += cluster



@if ( Cluster::node in Cluster::nodes ) &analyze

@load ./setup-connections

@if ( Cluster::local_node_type() == Cluster::MANAGER ) &analyze
@load ./nodes/manager
# If no logger is defined, then the manager receives logs.
@if ( Cluster::manager_is_logger ) &analyze
@load ./nodes/logger
@endif
@endif

@if ( Cluster::local_node_type() == Cluster::LOGGER ) &analyze
@load ./nodes/logger
@endif

@if ( Cluster::local_node_type() == Cluster::PROXY ) &analyze
@load ./nodes/proxy
@endif

@if ( Cluster::local_node_type() == Cluster::WORKER ) &analyze
@load ./nodes/worker
@endif

@load ./broker-stores.zeek

@endif
@endif
