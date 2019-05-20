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

@TEST-START-FILE configfile
testbool F
testcount    1
testcount 2
testcount 2
testint		-1
testenum Conn::LOG
testport 45
testaddr 127.0.0.1
testaddr 2607:f8b0:4005:801::200e
testinterval 60
testtime 1507321987
test_set a,b,c,d,erdbeerschnitzel
test_vector 1,2,3,4,5,6
test_set (empty)
test_set -
test_set_full 1,3,4,5,6,7
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

export {
	option testbool: bool = T;
	option testcount: count = 0;
	option testint: int = 0;
	option testenum = SSH::LOG;
	option testport = 42/tcp;
	option testaddr = 127.0.0.1;
	option testtime = network_time();
	option testinterval = 1sec;
	option teststring = "a";
	option test_set: set[string] = {};
	option test_set_full: set[count] = {1, 2, 3, 7, 10, 15};
	option test_vector: vector of count = {};
}

event zeek_init()
	{
	Config::read_config("../configfile");
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

function option_changed(ID: string, new_value: any, location: string): any
	{
	print "option changed", ID, new_value, location;
	return new_value;
	}

event zeek_init() &priority=5
	{
	Option::set_change_handler("testport", option_changed, -100);
	Option::set_change_handler("teststring", option_changed, -100);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event die()
	{
	terminate();
	}

event Cluster::node_up(name: string, id: string)
	{
	schedule 10sec { die() };
	}
@endif

module Config;

event Config::cluster_set_option(ID: string, val: any, location: string) &priority=-10
	{
	print "cluster_set_option", ID, val, location;
	}
