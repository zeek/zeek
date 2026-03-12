# @TEST-DOC: Ensure that a completely custom topic works with Broker. The manager also receives the changes.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: zeek --parse-only manager.zeek
# @TEST-EXEC: zeek --parse-only proxy.zeek
# @TEST-EXEC: zeek --parse-only worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run proxy "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy-1 zeek -b ../proxy.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./proxy/out
# @TEST-EXEC: btest-diff ./worker-1/out
# @TEST-EXEC: btest-diff ./worker-2/out


# @TEST-START-FILE common.zeek
@load frameworks/cluster/experimental

global endpoints: set[addr, addr] &write_expire=300sec &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	$topic="/my/custom/topic/endpoints",
	$max_batch_delay=100msec,  # Delay a bit longer after the first publish.
];

event zeek_init()
	{
	Cluster::subscribe("/my/custom/topic/");
	}

event start_test()
	{
	if ( Cluster::node == "worker-1" )
		{
		add endpoints[192.168.0.1, 10.0.0.1];
		add endpoints[192.168.0.2, 10.0.0.2];
		add endpoints[192.168.0.3, 10.0.0.3];
		}

	if ( Cluster::node == "worker-2" )
		{
		add endpoints[192.168.0.4, 10.0.0.4];
		add endpoints[192.168.0.5, 10.0.0.5];
		add endpoints[192.168.0.6, 10.0.0.6];
		}
	}

event do_terminate()
	{
	terminate();
	}

global done_test: event();
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_done = 0;
global nodes_down = 0;

event Cluster::Experimental::cluster_started()
	{
	print "cluster_started";
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
		terminate();
	}

event zeek_done()
	{
	print "zeek_done endpoints", |endpoints|;
	}
# @TEST-END-FILE

# @TEST-START-FILE proxy.zeek
@load ./common.zeek
# Proxy also receives the inserts like all other nodes, and we use it
# for hook logging.
hook Cluster::apply_table_change_infos_policy(tcheader: Cluster::TableChangeHeader, tcinfos: Cluster::TableChangeInfos)
	{
	print "apply_table_change_infos_policy", tcheader$id, |tcinfos|;
	}
event zeek_done()
	{
	print "zeek_done endpoints", |endpoints|;
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event zeek_init()
	{
	# Await for two entries inserted by the workers themselves and
	# one from the manager.
	when ( |endpoints| == 6 )
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
