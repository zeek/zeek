# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC: btest-diff manager/config.log

@load base/frameworks/config
@load policy/frameworks/cluster/experimental

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

@if ( Cluster::node == "worker-1" )
event Cluster::Experimental::cluster_started()
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
