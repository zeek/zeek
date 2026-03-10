# @TEST-DOC: Test that publish_table() on worker-1 to worker-2 works with Broker where we transparently send through the manager.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: zeek --parse-only manager.zeek
# @TEST-EXEC: zeek --parse-only worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: wait-for-file ./manager/ready 10
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out

# @TEST-START-FILE common.zeek
@load base/frameworks/cluster

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
