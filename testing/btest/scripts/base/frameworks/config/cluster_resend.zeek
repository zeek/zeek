# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: sleep 15
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC: btest-diff manager-1/config.log

# In this test we check if values get updated on a worker, even if they were set before the
# worker is present.

@load base/frameworks/config


@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1", $interface="eth1"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

export {
	option testport = 42/tcp;
	option teststring = "a";
	option testcount: count = 0;
}

global n = 0;

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

global ready_for_data: event();

event zeek_init()
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

@if ( Cluster::node == "manager-1" )
event ready_for_data()
	{
	Config::set_value("testcount", 1);
	}
@endif

event die()
	{
	terminate();
	}

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event Cluster::node_up(name: string, id: string)
	{
		print "Node up", name;
		if ( name == "worker-2" )
		schedule 5sec { die() };
	}
@endif

function option_changed(ID: string, new_value: any, location: string): any
	{
	print "option changed", ID, new_value, location;
	return new_value;
	}

event zeek_init() &priority=5
	{
	Option::set_change_handler("testport", option_changed, -100);
	Option::set_change_handler("teststring", option_changed, -100);
	Option::set_change_handler("testcount", option_changed, -100);
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;
event Cluster::node_up(name: string, id: string) &priority=-5
	{
	++peer_count;
	if ( peer_count == 1 )
		event ready_for_data();
	}

@endif

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
