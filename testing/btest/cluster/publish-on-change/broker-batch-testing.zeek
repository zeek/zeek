# @TEST-DOC: Stress test &publish_on_change by having all nodes insert 1000 individual entries, then have the manager clear it.
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

# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./proxy/out
# @TEST-EXEC: btest-diff ./worker-1/out
# @TEST-EXEC: btest-diff ./worker-2/out


# @TEST-START-FILE common.zeek
@load frameworks/cluster/experimental

global tbl1: table[string, count] of string &write_expire=300sec &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW, TABLE_ELEMENT_REMOVED),
	$max_batch_size=7,
	$max_batch_delay=0.5msec,
];


# Somewhat random insert to tickle different batching scenarios.
const insert_per_tick = 13;
const tick_delay = 0.3msec;
const total = 10;
global n = 0;

event tick()
	{
	local i = 0;
	while ( i < insert_per_tick )
		{
		if ( n == total )
			break;

		++i;
		++n;

		# Insert an entry into the table.
		tbl1[Cluster::node, n] = fmt("%s-%s", Cluster::node, n);
		}

	if ( n < total )
		schedule tick_delay { tick() };
	else
		print "done inserting", n;
	}

global done_test: event();

event start_test()
	{
	print "start_test";
	schedule tick_delay { tick() };

	# All nodes await 4000 entries.
	when ( |tbl1| == 40 )
		{
		if ( Cluster::node != "manager" )
			Cluster::publish(Cluster::manager_topic, done_test);
		else
			event done_test();

		# Wait for the manager to clear the table again.
		when ( |tbl1| == 0 )
			{
			print "tbl1 is now empty";
			terminate();
			}
		}
	timeout 10sec
		{
		Reporter::fatal(fmt("timeout (%s)", |tbl1|));
		}
	}

event zeek_done()
	{
	print "zeek_done", |tbl1|;
	}

# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_done = 0;
global nodes_down = 0;

event done_test()
	{
	++nodes_done;
	print "nodes_done", nodes_done;
	if ( nodes_done == 4 )
		{
		print "clear tbl1", |tbl1|;
		clear_table(tbl1);
		}
	}

event Cluster::Experimental::cluster_started()
	{
	Cluster::publish(Cluster::worker_topic, start_test);
	Cluster::publish(Cluster::proxy_topic, start_test);
	event start_test();
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
	print "zeek_done", |tbl1|;
	}
# @TEST-END-FILE

# @TEST-START-FILE proxy.zeek
@load ./common.zeek

# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek
# @TEST-END-FILE
