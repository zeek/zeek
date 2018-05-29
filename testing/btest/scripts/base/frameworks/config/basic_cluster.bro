# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait 10

@load base/frameworks/config


@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $interface="eth1"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

export {
	option testport = 42/tcp;
	option teststring = "a";
}

global n = 0;

event bro_init() &priority=5
	{
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

global ready_for_data: event();

event bro_init()
	{
	Broker::auto_publish(Cluster::worker_topic, ready_for_data);
	}

@if ( Cluster::node == "worker-1" )
event ready_for_data()
	{
	Config::set_value("testport", 44/tcp);
	Config::set_value("teststring", "b", "comment");
	}
@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;
event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peer_count;
	if ( peer_count == 2 )
		event ready_for_data();
	}

@endif
