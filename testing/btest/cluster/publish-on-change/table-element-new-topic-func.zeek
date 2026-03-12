# @TEST-DOC: Test a $topic_func to distribute state from manager to workers using Cluster::publish_hrw()
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek

# @TEST-EXEC: zeek --parse-only manager.zeek
# @TEST-EXEC: zeek --parse-only worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker-1/out
# @TEST-EXEC: btest-diff ./worker-2/out


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

function my_topic_func(k0: string, k1: string): string
	{
	local r = Cluster::hrw_topic(Cluster::worker_pool, cat(k0, k1));
	print fmt("my_topic_func(%s, %s) = %s", k0, k1, r);
	return r;
	}

global tbl1: table[string, string] of count &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	$topic=my_topic_func,
	$max_batch_size=0,
];

event do_terminate() &is_used
	{
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up = 0;
global nodes_down = 0;

event Cluster::node_up(name: string, id: string)
	{
	++nodes_up;
	print "nodes_up", nodes_up;
	if ( nodes_up == 2 )
		{
		# Insert a bunch of keys that are distributed
		# to the workers using my_topic_func()
		tbl1["a", "a"] = 1;
		tbl1["b", "z"] = 2;
		tbl1["c", "a"] = 3;
		tbl1["a", "b"] = 4;
		tbl1["b", "b"] = 5;
		tbl1["c", "b"] = 6;
		tbl1["a", "z"] = 7;
		tbl1["b", "c"] = 8;
		tbl1["c", "c"] = 9;
		tbl1["d", "d"] = 10;

		Cluster::publish(Cluster::worker_topic, do_terminate);
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;
	print "nodes_down", nodes_down;
	if ( nodes_down == 2 )
		terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek
event do_terminate() &priority=10
	{
	print "tbl1", tbl1;
	}
# @TEST-END-FILE
