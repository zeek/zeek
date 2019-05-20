# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC: btest-diff manager-1/config.log

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

event die()
	{
	terminate();
	}

function option_changed(ID: string, new_value: any, location: string): any
	{
	print "option changed", ID, new_value, location;
	schedule 5sec { die() };
	return new_value;
	}

event zeek_init() &priority=5
	{
	Option::set_change_handler("testport", option_changed, -100);
	Option::set_change_handler("teststring", option_changed, -100);
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;
event Cluster::node_up(name: string, id: string)
	{
	++peer_count;
	if ( peer_count == 2 )
		event ready_for_data();
	}

@endif
