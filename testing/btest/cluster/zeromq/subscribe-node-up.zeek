# @TEST-DOC: Startup a manager and four workers. The manager sends hello directly in the Cluster::node_up() event for each worker to a specific topic of a subscription created at priority=-100.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-3 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-3 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-4 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-4 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker-1/out
# @TEST-EXEC: btest-diff ./worker-2/out
# @TEST-EXEC: btest-diff ./worker-3/out
# @TEST-EXEC: btest-diff ./worker-4/out

# @TEST-START-FILE cluster-layout.zeek
# Custom cluster layout with a manager and 4 workers
redef Cluster::manager_is_logger = T;

redef Cluster::nodes = {
        ["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("LOG_PULL_PORT"))],
        ["worker-1"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
        ["worker-2"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
        ["worker-3"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
        ["worker-4"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
};

# @TEST-END-FILE

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global hello: event(name: string);
global finish: event(sender: string);

const test_topic = "test.topic";
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up = 0;
global nodes_down = 0;

event publish_finish()
	{
	print "publish finish";
	Cluster::publish(Cluster::worker_topic, finish, Cluster::node);
	}

event Cluster::node_up(name: string, id: string)
	{
	++nodes_up;
	print "nodes_up", nodes_up;

	# Send a hello event to the custom node topic directly
	# from within Cluster::node_up()
	local topic = test_topic + "." + name + ".";
	Cluster::publish(topic, hello, "Hello " + name + "!");

	if ( nodes_up == 4 )
		schedule 10msec { publish_finish() };
	}

event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;
	print "node_down", nodes_down;

	if ( nodes_down == 4 )
		terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event zeek_init() &priority=-100
	{
	local topic = test_topic + "." + Cluster::node + ".";
	print "subscribing to", topic;
	Cluster::subscribe(topic);
	}

event hello(msg: string) &is_used
	{
	print "got hello", msg;
	}

event finish(sender: string) &is_used
	{
	print "got finish from", sender;
	terminate();
	}
# @TEST-END-FILE
