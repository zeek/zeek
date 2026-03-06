# @TEST-DOC: Implements the apply_table_change_infos_policy() hook on the manager to observe incoming and removed entries.
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

global endpoints: set[addr, addr] &write_expire=300sec &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW, TABLE_ELEMENT_REMOVED),
];

event do_terminate()
	{
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up = 0;
global nodes_down = 0;

hook Cluster::apply_table_change_infos_policy(tcheader: Cluster::TableChangeHeader, tcinfos: Cluster::TableChangeInfos)
	{
	local id = tcheader$id;
	print "apply_table_change_infos_policy", id, |tcinfos|;
	for ( _, tci in tcinfos )
		print "table_change", id, tci;
	}

event Cluster::node_up(name: string, id: string)
	{
	++nodes_up;
	print "nodes_up", nodes_up;

	if ( nodes_up == 2 )
		{
		add endpoints[192.168.0.1, 10.0.0.1];
		add endpoints[192.168.0.2, 10.0.0.2];

		# Wait for the workers to add some more.
		when ( |endpoints| == 4 )
			{
			print "have 4 endpoints", endpoints;
			# Add one more, then wait for workers to empty endpoints.
			add endpoints[192.168.0.5, 10.0.0.5];

			when ( |endpoints| == 0 )
				{
				print "endpoints again empty", endpoints;
				Cluster::publish(Cluster::worker_topic, do_terminate);
				}
			timeout 10sec
				{
				Reporter::fatal("timeout 2");
				}
			}
		timeout 10sec
			{
			Reporter::fatal("timeout 1");
			}
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;
	print "nodes_down", nodes_down;

	if ( nodes_down == 2 )
		{
		print "end", endpoints;
		when ( |endpoints| == 0 )
			{
			terminate();
			}
		timeout 10sec
			{
			Reporter::fatal("timeout!");
			}
		}
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek
event delayed_add(a0: addr, a1: addr)
	{
	add endpoints[a0, a1];
	}

event delayed_delete()
	{
	for ( [k0, k1] in copy(endpoints) )
		delete endpoints[k0, k1];
	}

event zeek_init()
	{
	# Wait for two entries inserted by manager.
	when ( |endpoints| == 2 )
		{
		# Each worker inserts an entry. Do it delayed so that
		# worker-1 always inserts before worker-2. Yes?
		if ( Cluster::node == "worker-1" )
			schedule 5msec { delayed_add(192.168.0.3, 10.0.0.3) };
		if ( Cluster::node == "worker-2" )
			schedule 50msec { delayed_add(192.168.0.4, 10.0.0.4) };

		# Workers wait for their own and the managers insert.
		when ( |endpoints| == 5 )
			{
			print "now it is 5 endpoints";

			# worker-1 deletes them all which makes
			# the manager publish do_terminate()
			if ( Cluster::node == "worker-1" )
				schedule 50msec { delayed_delete() };
			}
		timeout 10sec
			{
			Reporter::fatal("timeout 2");
			}
		}
	timeout 10sec
		{
		Reporter::fatal("timeout 1");
		}
	}
# @TEST-END-FILE
