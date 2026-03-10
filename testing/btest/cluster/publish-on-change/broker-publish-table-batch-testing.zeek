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
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: wait-for-file ./worker-1/ready 10
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker-1/out
# @TEST-EXEC: btest-diff ./worker-2/out

# @TEST-START-FILE common.zeek
@load base/frameworks/cluster

redef Cluster::default_publish_table_batch_size = 3;
redef Cluster::default_table_publish_on_change_max_batch_size = 7;

global tbl1: table[string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	$topic=Cluster::worker_topic,
];
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event Cluster::node_up(name: string, id: string)
	{
	# If this node_up() event is for a worker, republish it so that
	# the test ends up working nicely.
	if ( name == "worker-2" )
		Cluster::publish(Cluster::node_topic("worker-1"), Cluster::node_up, name, id);
	}

global nodes_down = 0;
event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;

	if ( name == "worker-1" )
		Cluster::publish(Cluster::node_topic("worker-2"), Cluster::node_down, name, id);

	print "node_down", nodes_down;
	if ( nodes_down == 2 )
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

event Cluster::node_up(name: string, id: string)
	{
	if ( Cluster::node == "worker-1" )
		{
		if ( name == "manager" )
			{
			print "manager up";
			local i = 0;
			while ( i < 10 )
				{
				++i;
				tbl1[cat(i)] = cat(i);
				}
			print "populated table - marking ready";
			system("touch ready");
			}
		else if ( name == "worker-2" )
			{
			print "worker-2 up";
			Cluster::publish_table(Cluster::node_topic(name), tbl1);
			print "published table to worker-2";
			}
		}
	}

event zeek_init()
	{
	if ( Cluster::node == "worker-1" )
		{
		# Wait for worker-2 to add more elements. See below.
		when ( |tbl1| == 20 )
			{
			print fmt("table now populated to 20 (%s)", tbl1);
			terminate();
			}
		timeout 10sec
			{
			Reporter::fatal("timeout worker-1");
			}
		}
	else if ( Cluster::node == "worker-2" )
		{
		when ( |tbl1| == 10 )
			{
			print fmt("table populated to 10 (%s)", tbl1);
			local i = 9;
			while ( i < 20 )
				{
				++i;
				tbl1[cat(i)] = cat(i);
				}

			print "added 10 more elements!", |tbl1|;
			}
		timeout 10sec
			{
			Reporter::fatal("timeout worker-2");
			}
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	# A worker terminates as soon as another worker is down.
	if ( /worker-.*/ == name )
		terminate();
	}
# @TEST-END-FILE
