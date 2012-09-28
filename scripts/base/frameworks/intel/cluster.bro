##! Cluster transparency support for the intelligence framework.  This is mostly oriented
##! toward distributing intelligence information across clusters.

@load base/frameworks/cluster
@load ./input

module Intel;

# If this process is not a manager process, we don't want the full metadata
@if ( Cluster::local_node_type() != Cluster::MANAGER )
redef have_full_data = F;
@endif

global cluster_new_item: event(item: Item);
global cluster_updated_item: event(item: Item);

redef record Item += {
	## This field is solely used internally for cluster transparency with
	## the intelligence framework to avoid storms of intelligence data 
	## swirling forever.  It allows data to propagate only a single time.
	first_dispatch: bool &default=T;
};

# Primary intelligence distribution comes from manager.
redef Cluster::manager2worker_events += /^Intel::cluster_.*$/;
# If a worker finds intelligence and adds it, it should share it back to the manager.
redef Cluster::worker2manager_events += /^Intel::(cluster_.*|match_no_items)$/;

@if ( Cluster::local_node_type() != Cluster::MANAGER )
redef Intel::data_store &synchronized;
@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Intel::match_no_items(s: Seen) &priority=5
	{
	event Intel::match(s, Intel::get_items(s));
	}

global initial_sync = F;
event remote_connection_handshake_done(p: event_peer)
	{
	# Insert the data once something is connected.
	# This should only push the data to a single host where the 
	# normal Bro synchronization should take over.
	if ( ! initial_sync )
		{
		initial_sync = T;
		for ( net in data_store$net_data )
			event Intel::cluster_new_item([$net=net, $meta=[$source=""]]);
		for ( [str, str_type] in data_store$string_data )
			event Intel::cluster_new_item([$str=str, $str_type=str_type, $meta=[$source=""]]);
		}
	}
@endif

event Intel::cluster_new_item(item: Intel::Item) &priority=5
	{
	# Ignore locally generated events to avoid event storms.
	if ( is_remote_event() )
		Intel::insert(item);
	}

event Intel::cluster_updated_item(item: Intel::Item) &priority=5
	{
	# Ignore locally generated events to avoid event storms.
	if ( is_remote_event() )
		Intel::insert(item);
	}

event Intel::new_item(item: Intel::Item) &priority=5
	{
	# The cluster manager always rebroadcasts intelligence.
	# Workers redistribute it if it was locally generated on 
	# the worker.
	if ( Cluster::local_node_type() == Cluster::MANAGER ||
	     item$first_dispatch )
		{
		item$first_dispatch = F;
		event Intel::cluster_new_item(item);
		}
	}

event Intel::updated_item(item: Intel::Item) &priority=5
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
