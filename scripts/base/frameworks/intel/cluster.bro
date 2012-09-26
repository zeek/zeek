##! Cluster transparency support for the intelligence framework.  This is mostly oriented
##! toward distributing intelligence information across clusters.

@load base/frameworks/cluster

module Intel;

export {
	global cluster_new_item: event(item: Item);
	global cluster_updated_item: event(item: Item);

	redef record Item += {
		## This field is solely used internally for cluster transparency with
		## the intelligence framework to avoid storms of intelligence data 
		## swirling forever.  It allows data to propagate only a single time.
		first_dispatch: bool &default=T;
	};
}

# If this process is not a manager process, we don't want the full metadata
@if ( Cluster::local_node_type() != Cluster::MANAGER )
redef store_metadata = F;
@endif

# Primary intelligence distribution comes from manager.
redef Cluster::manager2worker_events += /Intel::cluster_(new|updated)_item/;
# If a worker finds intelligence and adds it, it should share it back to the manager.
redef Cluster::worker2manager_events += /Intel::(match_in_.*_no_items|cluster_(new|updated)_item)/;

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Intel::match_in_conn_no_items(c: connection, found: Found)
	{
	local items = lookup(found);
	event Intel::match_in_conn(c, found, items);
	}
@endif

event Intel::cluster_new_item(item: Intel::Item)
	{
	# Ignore locally generated events.
	if ( is_remote_event() )
		Intel::insert(item);
	}

event Intel::cluster_updated_item(item: Intel::Item)
	{
	# Ignore locally generated events.
	if ( is_remote_event() )
		Intel::insert(item);
	}

event Intel::new_item(item: Intel::Item)
	{
	# The cluster manager always rebroadcasts intelligence
	if ( Cluster::local_node_type() == Cluster::MANAGER ||
	     item$first_dispatch )
		{
		item$first_dispatch = F;
		event Intel::cluster_new_item(item);
		}
	}

event Intel::updated_item(item: Intel::Item)
	{
	# If this is the first time this item has been dispatched or this
	# is a manager, send it over the cluster.
	if ( Cluster::local_node_type() == Cluster::MANAGER ||
	     item$first_dispatch )
		{
		item$first_dispatch = F;
		event Intel::cluster_updated_item(item);
		}
	}
