@load ./main

# The cluster framework must be loaded first.
@load base/frameworks/cluster

@if ( Cluster::is_enabled() )
@load ./cluster
@endif

# This needs cluster support to only read on the manager.
@load ./input
