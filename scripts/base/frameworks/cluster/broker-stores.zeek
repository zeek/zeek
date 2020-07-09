@load ./main

module Broker;

export {
	global announce_masters: event(masters: set[string]);
}

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
redef Broker::auto_store_master = F;
@endif

@if ( Broker::auto_store_master )

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

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=1
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
		local name = "___sync_store_" + i;
		Broker::create_clone(name);
		}
	}

@endif
