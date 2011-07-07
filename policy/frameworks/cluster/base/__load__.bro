@load frameworks/cluster/base/main

@if ( Cluster::node != "" )

# Only load the communication framework if it really looks like someone is
# trying to start up a cluster node.
@load frameworks/communication

## If this script isn't found anywhere, the cluster bombs out.
## Loading the cluster framework requires that a script by this name exists
## somewhere in the BROPATH.  The only thing in the file should be the
## cluster definition in the :bro:id:`Cluster::nodes` variable.
@load cluster-layout

@if ( Cluster::node in Cluster::nodes )

@load frameworks/cluster/base/external-events
@load frameworks/cluster/base/setup-connections

# Don't start the listening process until we're a bit more sure that the
# cluster framework is actually being enabled.
@load frameworks/communication/listen-clear

@if ( Cluster::nodes[Cluster::node]$node_type == Cluster::MANAGER )
@load frameworks/cluster/base/node/manager
@endif

@if ( Cluster::nodes[Cluster::node]$node_type == Cluster::PROXY )
@load frameworks/cluster/base/node/proxy
@endif

@if ( Cluster::nodes[Cluster::node]$node_type == Cluster::WORKER )
@load frameworks/cluster/base/node/worker
@endif

@endif
@endif