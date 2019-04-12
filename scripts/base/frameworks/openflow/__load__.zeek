@load ./consts
@load ./types
@load ./main
@load ./plugins

# The cluster framework must be loaded first.
@load base/frameworks/cluster

@if ( Cluster::is_enabled() )
@load ./cluster
@else
@load ./non-cluster
@endif
