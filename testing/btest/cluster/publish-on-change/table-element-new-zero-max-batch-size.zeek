# @TEST-DOC: Test the max_batch_size=0 and look at the hook output on the worker to see if the manager published properly.
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
@load ./zeromq-test-bootstrap

global tbl1: table[string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	$max_batch_size=0,
];

hook Cluster::apply_table_change_infos_policy(tcheader: Cluster::TableChangeHeader, tcinfos: Cluster::TableChangeInfos)
	{
	local id = tcheader$id;
	print "apply_table_change_infos_policy", id, |tcinfos|;
	for ( _, tci in tcinfos )
		print "table_change", id, tci;
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;

	# Insert 10 entries, should all be published with a single event.
	local i = 0;
	while ( i < 10 )
		{
		++i;
		local key = fmt("from-manager-%s", i);
		tbl1[key] = "from-manager";
		}

	# Wait for the worker to insert "y" into the table.
	when ( "from-worker-10" in tbl1 )
		{
		tbl1["from-manager-11"] = "from manager, finish!";
		}
	timeout 10sec
		{
		Reporter::fatal("timeout");
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
	when ( "from-manager-10" in tbl1 )
		{
		local i = 0;
		while ( i < 10 )
			{
			++i;
			local key = fmt("from-worker-%s", i);
			tbl1[key] = "from-worker";
			}
		when ( "from-manager-11" in tbl1 )
			{
			print "tbl1 now contains from-manager-11, too", tbl1;

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
