@load ./main
@load ./input

# The cluster framework must be loaded first.
@load base/frameworks/cluster

@if ( Cluster::is_enabled() )
@load ./cluster
@endif

@load ./plugins/dns_zones
