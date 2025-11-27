# @TEST-DOC: Regression test for shared unsubscriptions not happening.
#
# Scenario:
# * manager waits for two workers and sends start_test() event
# * workers create subscriptions for /test/worker-1, /test/worker-2 and /test/worker-common
# * manager: Seeing all these subscriptions, subscribe to /test/manager-common
# * workers: Seeing /test/manager-common subscription, unsubscribe /test/worker-common
# * manager: Observes unsubscription for /test/worker-common, unsubscribes from /test/manager-common
# * workers: terminate() when seeing the unsubscription for /test/manager-common
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: REP_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek --parse-only ./manager.zeek ./worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff ./manager/out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff ./worker-1/out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff ./worker-2/out


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global start_test: event() &is_used;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global worker_subs_seen = 0;
global worker_common_seen = F;
global subscribe_done = F;
global nodes_up = 0;
global nodes_down = 0;

event Cluster::Backend::ZeroMQ::subscription(topic: string)
	{
	if ( ! starts_with(topic, "/test/worker") )
		return;

	print "B subscription", topic;

	if ( topic == "/test/worker-1" || topic == "/test/worker-2" )
		++worker_subs_seen;

	if ( topic == "/test/worker-common" )
		worker_common_seen = T;

	if ( ! subscribe_done && worker_common_seen && worker_subs_seen == 2 )
		{
		print "C subscribing to /test/manager-common";
		Cluster::subscribe("/test/manager-common");
		subscribe_done = T;
		}
	}

event Cluster::Backend::ZeroMQ::unsubscription(topic: string)
	{
	if ( ! starts_with(topic, "/test/worker") )
		return;

	print "D unsubscription", topic;

	if ( topic == "/test/worker-common" )
		{
		print "E unsubscribing from /test/manager-common";
		Cluster::unsubscribe("/test/manager-common");
		}
	}

event Cluster::node_up(name: string, id: string)
	{
	print "A node_up", name;
	++nodes_up;

	if ( nodes_up == 2 )
		Cluster::publish(Cluster::worker_topic, start_test);
	}

event Cluster::node_down(name: string, id: string)
	{
	print "Z node_down", name;
	++nodes_down;
	if ( nodes_down == 2 )
		terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event start_test()
	{
	print "A start_test";
	Cluster::subscribe("/test/worker-common");
	Cluster::subscribe("/test/" + Cluster::node);
	}

event Cluster::Backend::ZeroMQ::subscription(topic: string)
	{
	if ( ! starts_with(topic, "/test/manager") )
		return;

	print "B subscription", topic;

	if ( topic == "/test/manager-common" )
		{
		print "C unsubscribe from /test/worker-common";
		Cluster::unsubscribe("/test/worker-common");
		}
	}

event Cluster::Backend::ZeroMQ::unsubscription(topic: string)
	{
	if ( ! starts_with(topic, "/test/manager") )
		return;

	print "C unsubscription", topic;

	if ( topic == "/test/manager-common" )
		{
		print "D /test/manager-common unsubscribed, terminate()";
		terminate();
		}
	}
# @TEST-END-FILE
