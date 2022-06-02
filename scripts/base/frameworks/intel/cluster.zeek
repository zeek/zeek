##! Cluster transparency support for the intelligence framework.  This is mostly
##! oriented toward distributing intelligence information across clusters.

@load ./main
@load base/frameworks/cluster

module Intel;

# Internal events for cluster data distribution.  Marked as &is_used since
# they're communicated via Broker.
global insert_item: event(item: Item) &is_used;
global insert_indicator: event(item: Item) &is_used;

# By default the manager sends its current min_data_store to connecting workers.
# During testing it's handy to suppress this, since receipt of the store
# introduces nondeterminism when mixed with explicit data insertions.
const send_store_on_node_up = T &redef;

# If this process is not a manager process, we don't want the full metadata.
@if ( Cluster::local_node_type() != Cluster::MANAGER )
redef have_full_data = F;
@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init()
	{
	Broker::auto_publish(Cluster::worker_topic, remove_indicator);
	}

# Handling of new worker nodes.
event Cluster::node_up(name: string, id: string)
	{
	# When a worker connects, send it the complete minimal data store unless
	# we turned off that feature. The store will be kept up to date after
	# this by the insert_indicator event.
	if ( send_store_on_node_up && name in Cluster::nodes && Cluster::nodes[name]$node_type == Cluster::WORKER )
		{
		Broker::publish_id(Cluster::node_topic(name), "Intel::min_data_store");
		}
	}

# On the manager, the new_item event indicates a new indicator that
# has to be distributed.
event Intel::new_item(item: Item) &priority=5
	{
	local pt = Cluster::rr_topic(Cluster::proxy_pool, "intel_insert_rr_key");

	if ( pt == "" )
		# No proxies alive, publish to all workers ourself instead of
		# relaying via a proxy.
		pt = Cluster::worker_topic;

	Broker::publish(pt, Intel::insert_indicator, item);
	}

# Handling of item insertion triggered by remote node.
event Intel::insert_item(item: Intel::Item) &priority=5
	{
	Intel::_insert(item, T);
	}

# Handling of item removal triggered by remote node.
event Intel::remove_item(item: Item, purge_indicator: bool) &priority=5
	{
	remove(item, purge_indicator);
	}

# Handling of match triggered by remote node.
event Intel::match_remote(s: Seen) &priority=5
	{
	if ( Intel::find(s) )
		event Intel::match(s, Intel::get_items(s));
	}
@endif

@if ( Cluster::local_node_type() == Cluster::WORKER )
event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, match_remote);
	Broker::auto_publish(Cluster::manager_topic, remove_item);
	}

# On a worker, the new_item event requires to trigger the insertion
# on the manager to update the back-end data store.
event Intel::new_item(item: Intel::Item) &priority=5
	{
	Broker::publish(Cluster::manager_topic, Intel::insert_item, item);
	}

# Handling of new indicators published by the manager.
event Intel::insert_indicator(item: Intel::Item) &priority=5
	{
	Intel::_insert(item, F);
	}
@endif

@if ( Cluster::local_node_type() == Cluster::PROXY )
event Intel::insert_indicator(item: Intel::Item) &priority=5
	{
	# Just forwarding from manager to workers.
	Broker::publish(Cluster::worker_topic, Intel::insert_indicator, item);
	}
@endif

