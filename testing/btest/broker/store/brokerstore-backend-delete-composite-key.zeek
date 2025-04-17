# @TEST-DOC: Test deletion of elements in a broker backed table with composite keys. Regression test for #3342.
#
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
#
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout

@load policy/frameworks/cluster/experimental

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
};
# @TEST-END-FILE

function change_handler(t: table[string, count] of count, tpe: TableChange,
			k0: string, k1: count, v: count)
	{
	print Cluster::node, "change_handler", tpe, k0, k1, v;

	# Terminate the manager when it sees the removed table element.
	if ( tpe == TABLE_ELEMENT_REMOVED && Cluster::local_node_type() == Cluster::MANAGER )
		terminate();
	}

global t: table[string, count] of count &backend=Broker::MEMORY &on_change=change_handler;

event zeek_done()
	{
	print Cluster::node, "zeek_done", t;
	}

# The worker populates the broker backed table and deletes a single entry,
# then waits on the manager before terminating itself.
@if ( Cluster::local_node_type() == Cluster::WORKER )
event do_delete()
	{
	delete t["b", 2];
	}

event Cluster::Experimental::cluster_started()
	{
	print "Got cluster_started event";
	t["a", 1] = 12;
	t["b", 2] = 23;
	t["c", 3] = 42;

	schedule 0.01sec { do_delete() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print Cluster::node, "peer_lost";
	terminate();
	}
@endif
