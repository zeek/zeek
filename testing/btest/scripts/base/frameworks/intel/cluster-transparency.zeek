# This test verifies intel data propagation via a cluster. The manager and both
# workers insert intel items, and both workers do lookups that we expect to hit.

# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff worker-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff worker-2/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-timestamps-and-sort btest-diff manager/intel.log

@load policy/frameworks/cluster/experimental
@load base/frameworks/intel

module Intel;

redef Log::default_rotation_interval=0sec;

event Cluster::Experimental::cluster_started()
	{
	# Insert the data once both workers are connected.
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		Intel::insert([$indicator="1.2.3.4", $indicator_type=Intel::ADDR, $meta=[$source="manager"]]);
	}

global log_writes = 0;
global worker_data = 0;
global sent_data = F;

# Watch for new indicators send to workers.
event Intel::insert_indicator(item: Intel::Item)
	{
	print fmt("new_indicator: %s inserted by %s", item$indicator, item$meta$source);

	if ( ! sent_data )
		{
		# We wait to insert data here because we can now be sure the 
		# full cluster is constructed.
		sent_data = T;
		if ( Cluster::node == "worker-1" )
			Intel::insert([$indicator="123.123.123.123", $indicator_type=Intel::ADDR, $meta=[$source="worker-1"]]);
		if ( Cluster::node == "worker-2" )
			Intel::insert([$indicator="4.3.2.1", $indicator_type=Intel::ADDR, $meta=[$source="worker-2"]]);
		}

	# Each worker does a lookup when it has 3 intel items which were
	# distributed over the cluster (data inserted locally is resent).
	# Worker 1 observes the host inserted by worker 2, and vice versa.
	if ( Cluster::node == "worker-1" )
		{
		if ( ++worker_data == 3 )
			{
			print "seeing 4.3.2.1";
			Intel::seen([$host=4.3.2.1, $where=Intel::IN_ANYWHERE]);
			}
		}

	if ( Cluster::node == "worker-2" )
		{
		if ( ++worker_data == 3 )
			{
			print "seeing 123.123.123.123";
			Intel::seen([$host=123.123.123.123, $where=Intel::IN_ANYWHERE]);
			}
		}
	}

# Watch for remote inserts sent to the manager.
event Intel::insert_item(item: Intel::Item)
	{
	print fmt("insert_item: %s inserted by %s", item$indicator, item$meta$source);
	}

# Watch for new items.
event Intel::new_item(item: Intel::Item)
	{
	print fmt("new_item triggered for %s by %s on %s", item$indicator,
			item$meta$source, Cluster::node);
	}

event Intel::log_intel(rec: Intel::Info)
	{
	if ( ++log_writes == 2 )
		terminate();
	}

event Cluster::node_down(name: string, id: string)
	{
	# Cascading termination
	terminate();
	}
