@load ./main
@load ./weird

# There should be no overhead imposed by loading notice actions so we
# load them all.
@load ./actions/drop
@load ./actions/email_admin
@load ./actions/page
@load ./actions/add-geodata

# There shouldn't be any default overhead from loading these since they 
# *should* only do anything when notices have the ACTION_EMAIL action applied.
@load ./extend-email/hostnames

# The cluster framework must be loaded first.
@load base/frameworks/cluster

@if ( Cluster::is_enabled() )
@load ./cluster
@else
@load ./non-cluster
@endif

# Load here so that it can check whether clustering is enabled.
@load ./actions/pp-alarms