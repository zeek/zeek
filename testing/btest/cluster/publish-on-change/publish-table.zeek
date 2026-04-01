# @TEST-DOC: Test Cluster::publish_table() from manager to worker. Start the manager. Fill the table, then spawn the worker. The manager sends the table using Cluster::publish_table()
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
# @TEST-EXEC: wait-for-file ./manager/ready 10


# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global tbl1: table[string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
];
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event zeek_init()
	{
	print "zeek_init";
	tbl1["x"] = "from manager";
	system("touch ready");

	# Wait for the worker to insert "y" into the table.
	when ( "y" in tbl1 )
		{
		print "tbl1 now contains y", tbl1;
		tbl1["z"] = "from manager, take two!";
		}
	timeout 10sec
		{
		Reporter::fatal("timeout");
		}
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;

	print "publish_table", tbl1;
	Cluster::publish_table(Cluster::nodeid_topic(id), tbl1);
	}

event Cluster::node_down(name: string, id: string)
	{
	print "node_down", name;
	terminate();
	}

# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

hook Cluster::apply_table_change_infos_policy(tcheader: Cluster::TableChangeHeader, tcinfos: Cluster::TableChangeInfos)
	{
	local id = tcheader$id;
	print "apply_table_change_infos_policy", id, |tcinfos|;
	for ( _, tci in tcinfos )
		print "table_change", id, tci;
	}

event zeek_init()
	{
	when ( "x" in tbl1 )
		{
		print "tbl1 now contains x", tbl1;
		tbl1["y"] = "from worker";

		when ( "z" in tbl1 )
			{
			print "tbl1 now contains z, too", tbl1;

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
