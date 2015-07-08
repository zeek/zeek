@load ./types
@load ./main
@load ./plugins
@load ./catch-and-release

# The cluster framework must be loaded first.
@load base/frameworks/cluster

@if ( Cluster::is_enabled() )
@load ./cluster
@else
@load ./non-cluster
@endif
