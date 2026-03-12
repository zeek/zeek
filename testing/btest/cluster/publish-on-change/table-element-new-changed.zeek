# @TEST-DOC: Test &publish_on_change with TABLE_ELEMENT_CHANGED
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
# @TEST-EXEC: zeek --parse-only proxy.zeek
# @TEST-EXEC: zeek --parse-only worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run proxy "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy zeek -b ../proxy.zeek >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./proxy/out
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global tbl1: table[string] of count &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW, TABLE_ELEMENT_CHANGED),
];
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
		print "set x to 42";
		tbl1["x"] = 42;

		# Wait for the worker to update x to 4711
		when ( tbl1["x"] == 4711 )
			{
			print "x is now 4711!", tbl1;
			# Override it.
			print "set x to 14711 for the worker to terminate";
			tbl1["x"] = 14711;
			}
		timeout 10sec
			{
			Reporter::fatal("timeout");
			}
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

# @TEST-START-FILE proxy.zeek
@load ./common.zeek
event zeek_init()
	{
	# The proxy just waits for the final value.
	when ( "x" in tbl1 && tbl1["x"] == 14711 )
		{
		print "x is now 14711", tbl1;

		terminate();
		}
	timeout 10sec
		{
		Reporter::fatal("timeout 2!");
		}
	}

# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event zeek_init()
	{
	when ( "x" in tbl1 )
		{
		print "tbl1 now contains x", tbl1;

		# We set it to 4711
		print "set x to 4711";
		tbl1["x"] = 4711;

		# Wait for the manager to update to 14711
		when ( tbl1["x"] == 14711 )
			{
			print "x is now 14711", tbl1;

			terminate();
			}
		timeout 10sec
			{
			Reporter::fatal("timeout 2!");
			}
		}
	timeout 10sec
		{
		Reporter::fatal("timeout 1!");
		}
	}
# @TEST-END-FILE
