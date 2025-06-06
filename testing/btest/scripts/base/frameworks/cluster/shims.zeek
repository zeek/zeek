# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
# @TEST-PORT: BROKER_PORT5
#
# @TEST-EXEC: zeek --parse-only %INPUT
#
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 5
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@load base/frameworks/cluster

@load policy/frameworks/cluster/experimental

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["proxy-2"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT4")), $manager="manager-1"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT5")), $manager="manager-1"],
};
@TEST-END-FILE

global got_pings = 0;

event zeek_init() {
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::subscribe("/manager/ping");
	else
		Cluster::subscribe("/other/ping");
}

event ping(msg: string) {
	print "ping", msg;
	++got_pings;

	if ( Cluster::local_node_type() == Cluster::MANAGER )
		{
		if ( got_pings == 4 )
			Cluster::publish("/other/ping", ping, "end");
		}
	else
		{
			if ( msg != "end")
				Cluster::publish("/manager/ping", ping, "reply");
			else
				{
				print "terminate";
				terminate();
				}
		}
}


event Cluster::Experimental::cluster_started()
	{
	print "started";

	if ( Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::publish("/other/ping", ping, "hello");
	}

global node_downs = 0;

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;
	++node_downs;
	print "node_down", node_downs;
	if ( node_downs == 4 )
		terminate();
	}
