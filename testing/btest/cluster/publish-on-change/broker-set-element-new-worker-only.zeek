# @TEST-DOC: Test that $topic=Cluster::worker_topic also works for Broker.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .

# @TEST-EXEC: zeek --parse-only manager.zeek
# @TEST-EXEC: zeek --parse-only worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run proxy "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy-1 zeek -b ../proxy.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-wait 5

# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./proxy/out
# @TEST-EXEC: btest-diff ./worker-1/out
# @TEST-EXEC: btest-diff ./worker-2/out


# @TEST-START-FILE common.zeek
global endpoints: set[addr, addr] &write_expire=300sec &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	# Changes are only published to the Cluster::worker_topic
	$topic=Cluster::worker_topic,
];

event start_test()
	{
	if ( Cluster::node == "worker-1" )
		add endpoints[192.168.0.1, 10.0.0.1];

	if ( Cluster::node == "worker-2" )
		add endpoints[192.168.0.2, 10.0.0.2];
	}

event do_terminate()
	{
	terminate();
	}

global done_test: event();
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up = 0;
global nodes_done = 0;
global nodes_down = 0;

event Cluster::node_up(name: string, id: string)
	{
	++nodes_up;
	print "nodes_up", nodes_up;

	if ( nodes_up == 3 )
		Cluster::publish(Cluster::worker_topic, start_test);
	}

event done_test()
	{
	++nodes_done;
	print "nodes_done", nodes_done;
	if ( nodes_done == 2 )
		{
		Cluster::publish(Cluster::proxy_topic, do_terminate);
		Cluster::publish(Cluster::worker_topic, do_terminate);
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;
	print "nodes_down", nodes_down;

	if ( nodes_down == 3 )
		{
		if ( |endpoints| != 0 )
			print fmt("ERROR: endpoints not empty: %s", endpoints);

		terminate();
		}
	}

event zeek_done()
	{
	print "zeek_done endpoints", endpoints;
	if ( |endpoints| != 0 )
		print fmt("ERROR: endpoints not empty: %s", endpoints);
	}
# @TEST-END-FILE

# @TEST-START-FILE proxy.zeek
@load ./common.zeek
# Proxy does nothing, but receives do_terminate() and prints its endpoint
# table which should be empty.
event zeek_done()
	{
	print "zeek_done endpoints", endpoints;
	if ( |endpoints| != 0 )
		print fmt("ERROR: endpoints not empty: %s", endpoints);
	}

# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event zeek_init()
	{
	# Await for two entries inserted by the workers themselves.
	when ( |endpoints| == 2 )
		{
		print "end", endpoints;
		Cluster::publish(Cluster::manager_topic, done_test);
		}
	timeout 10sec
		{
		Reporter::fatal("timeout!");
		}
	}

event zeek_done()
	{
	print "zeek_done", endpoints;
	}
# @TEST-END-FILE
