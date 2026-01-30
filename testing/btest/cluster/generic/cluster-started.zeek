# @TEST-DOC: Test cluster_started with ZeroMQ (but should work with any non-Broker backend that has global pubsub visibility)
#
# @TEST-REQUIRES: have-zeromq

# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run logger "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=logger zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run proxy "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../other.zeek >out"

# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: TEST_DIFF_CANONIFIER=sort btest-diff manager/out
# @TEST-EXEC: btest-diff logger/out
# @TEST-EXEC: btest-diff proxy/out
# @TEST-EXEC: btest-diff worker-1/out
# @TEST-EXEC: btest-diff worker-2/out

# @TEST-START-FILE common.zeek
@load zeromq-test-bootstrap
@load frameworks/cluster/experimental

redef Log::default_rotation_interval = 0.0sec;

event Cluster::Experimental::cluster_started()
	{
	print "B) cluster_started";
	}

event zeek_init()
	{
	Cluster::subscribe("control");
	}

# Helper event to terminate
event do_terminate() &is_used
	{
	print "Z) got do_terminate";
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common
event Cluster::Experimental::node_fully_connected(name: string, id: string, resending: bool)
	{
	print "A) node_fully_connected", name, resending;
	}

event Cluster::Experimental::cluster_started() &priority=-5
	{
	print "C) publish do_terminate()";
	Cluster::publish("control", do_terminate);
	}

# Shutdown manager when all other nodes are gone so that the XPUB/XSUB
# socket shuts down last. It is run by the manager.
global nodes_down: set[string] = {};

event Cluster::node_down(name: string, id: string)
	{
	add nodes_down[name];
	if ( | nodes_down| == |Cluster::nodes| - 1 )
		{
		print "Z) all nodes down";
		terminate();
		}
	}
# @TEST-END-FILE

# @TEST-START-FILE other.zeek
@load ./common
# @TEST-END-FILE
