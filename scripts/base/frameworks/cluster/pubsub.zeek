# A script that can be loaded by other scripts to access the publish subscribe API.

@load ./types

module Cluster;

export {
	## Subscribe to the given topic.
	##
	## topic: The topic to subscribe to.
	##
	## Returns: T on success, else F.
	global subscribe: function(topic: string): bool;

	## Unsubscribe from the given topic.
	##
	## topic: The topic to unsubscribe from.
	##
	## Returns: T on success, else F.
	global unsubscribe: function(topic: string): bool;

	## A hook invoked for every :zeek:see:`Cluster::subscribe` call.
	##
	## Breaking from this hook has no effect.
	##
	## topic: The topic string as given to :zeek:see:`Cluster::subscribe`.
	global on_subscribe: hook(topic: string);

	## A hook invoked for every :zeek:see:`Cluster::subscribe` call.
	##
	## Breaking from this hook has no effect.
	##
	## topic: The topic string as given to :zeek:see:`Cluster::subscribe`.
	global on_unsubscribe: hook(topic: string);
}

# base/bif/cluster.bif.zeek generated from from src/cluster/cluster.bif contains the
# Cluster::publish(), Cluster::publish_hrw() and Cluster::publish_rr() APIs
@load base/bif/cluster.bif

function subscribe(topic: string): bool
	{
	return Cluster::__subscribe(topic);
	}

function unsubscribe(topic: string): bool
	{
	return Cluster::__unsubscribe(topic);
	}
