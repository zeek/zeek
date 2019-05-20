# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run proxy-1  BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek %INPUT
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff manager-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff worker-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff worker-2/.stdout
# @TEST-EXEC: btest-diff manager-1/intel.log

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
	["proxy-1"]  = [$node_type=Cluster::PROXY,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT4")), $manager="manager-1"],
};
@TEST-END-FILE

module Intel;

redef Log::default_rotation_interval=0sec;

event Cluster::node_up(name: string, id: string)
	{
	# Insert the data once both workers are connected.
	if ( Cluster::local_node_type() == Cluster::MANAGER && Cluster::worker_count == 2 && Cluster::proxy_pool$alive_count == 1 )
		{
		Intel::insert([$indicator="1.2.3.4", $indicator_type=Intel::ADDR, $meta=[$source="manager"]]);
		}
	}

global worker2_data = 0;
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

	# We're forcing worker-2 to do a lookup when it has three intelligence items
	# which were distributed over the cluster (data inserted locally is resent).
	if ( Cluster::node == "worker-2" )
		{
		++worker2_data;
		if ( worker2_data == 3 )
			{
			# Now that everything is inserted, see if we can match on the data inserted
			# by worker-1.
			print "Doing a lookup";
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
	terminate();
	}

event Cluster::node_down(name: string, id: string)
	{
	# Cascading termination
	terminate();
	}
