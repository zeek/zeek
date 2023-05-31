##! This script deals with the cluster parts of Broker backed Zeek tables.
##! It makes sure that the master store is set correctly and that clones
##! are automatically created on the non-manager nodes.

# Note - this script should become unnecessary in the future, when we just can
# speculatively attach clones. This should be possible once the new ALM Broker
# transport becomes available.

@load ./main

module Broker;

export {
	## Event that is used by the manager to announce the master stores for Broker backed
	## tables.
	global announce_masters: event(masters: set[string]);
}

# If we are not the manager, disable automatically generating masters. We will attach
# clones instead.
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
redef Broker::table_store_master = F;
@endif

@if ( Broker::table_store_master )

global broker_backed_ids: set[string];

event zeek_init()
	{
	local globals = global_ids();
	for ( id in globals )
		{
		if ( globals[id]$broker_backend )
			add broker_backed_ids[id];
		}
	}

# Send the auto masters we created to the newly connected node
# Note: this is specifically chosen to be higher priority than the
# Broker::peer_added event in cluster/main.zeek which sends the
# Cluster::hello event to prevent a race on whether that Cluster::hello
# ends up generating Cluster::node_up before Broker::announce_masters.
event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=11
	{
	if ( ! Cluster::is_enabled() )
		return;

	local e = Broker::make_event(Broker::announce_masters, broker_backed_ids);
	Broker::publish(Cluster::nodeid_topic(endpoint$id), e);
	}

@else

event Broker::announce_masters(masters: set[string])
	{
	for ( i in masters )
		{
		# this magic name for the store is created in broker/Manager.cc for the manager.
		local name = "___sync_store_" + i;
		Broker::create_clone(name);
		}
	}

@endif
