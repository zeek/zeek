##! Cluster transparency support for the intelligence framework.  This is mostly
##! oriented toward distributing intelligence information across clusters.

@load base/frameworks/cluster
@load ./input

module Intel;

redef record Item += {
	## This field is used internally for cluster transparency to avoid 
	## re-dispatching intelligence items over and over from workers.
	first_dispatch: bool &default=T;
};

# If this process is not a manager process, we don't want the full metadata
@if ( Cluster::local_node_type() != Cluster::MANAGER )
redef have_full_data = F;
@endif

global cluster_new_item: event(item: Item);

# Primary intelligence distribution comes from manager.
redef Cluster::manager2worker_events += /^Intel::(cluster_new_item)$/;
# If a worker finds intelligence and adds it, it should share it back to the manager.
redef Cluster::worker2manager_events += /^Intel::(cluster_new_item|match_no_items)$/;

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Intel::match_no_items(s: Seen) &priority=5
	{
	event Intel::match(s, Intel::get_items(s));
	}

event remote_connection_handshake_done(p: event_peer)
	{
	# When a worker connects, send it the complete minimal data store.
	# It will be kept up to date after this by the cluster_new_item event.
	if ( Cluster::nodes[p$descr]$node_type == Cluster::WORKER )
		{
		send_id(p, "Intel::min_data_store");
		}
	}
@endif

event Intel::cluster_new_item(item: Intel::Item) &priority=5
	{
	# Ignore locally generated events to avoid event storms.
	if ( is_remote_event() )
		Intel::insert(item);
	}

event Intel::new_item(item: Intel::Item) &priority=5
	{
	# The cluster manager always rebroadcasts intelligence.
	# Workers redistribute it if it was locally generated.
	if ( Cluster::local_node_type() == Cluster::MANAGER ||
	     item$first_dispatch )
		{
		item$first_dispatch=F;
		event Intel::cluster_new_item(item);
		}
	}
