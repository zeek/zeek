# @TEST-DOC: Test &publish_on_change with TABLE_ELEMENT_NEW and TABLE_ELEMENT_DELETE.
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
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load base/frameworks/cluster

@load ./zeromq-test-bootstrap

global tbl1: table[string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW, TABLE_ELEMENT_REMOVED),
];
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	tbl1["x"] = "from manager";

	# Wait for the worker to insert "y" into the table.
	when ( "y" in tbl1 )
		{
		print "tbl1 now contains y", tbl1;
		clear_table(tbl1);
		}
	timeout 10sec
		{
		Reporter::fatal("timeout!");
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	print "node_down", name;
	terminate();
	}

# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event zeek_init()
	{
	when ( "x" in tbl1 )
		{
		print "tbl1 now contains x", tbl1;
		tbl1["y"] = "from worker";

		# Wait for manager to wipe the table after
		# it saw the "y" insert.
		when ( |tbl1| == 0 )
			{
			print "tbl1 now empty!";
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
