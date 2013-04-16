@load ./main
@load ./plugins

# The cluster framework must be loaded first.
@load base/frameworks/cluster

# Load either the cluster support script or the non-cluster support script.
@if ( Cluster::is_enabled() )
@load ./cluster
@else
@load ./non-cluster
@endif