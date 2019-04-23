# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: btest-bg-wait -k 13
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff manager-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff manager-1/intel.log

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
};
# @TEST-END-FILE

module Intel;

redef Log::default_rotation_interval=0sec;

event test_manager()
	{
	Intel::remove([$indicator="192.168.0.1", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::seen([$host=192.168.0.1, $where=Intel::IN_ANYWHERE]);
	Intel::remove([$indicator="192.168.0.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]], T);
	Intel::seen([$host=192.168.0.2, $where=Intel::IN_ANYWHERE]);
	}

event test_worker()
	{
	Intel::remove([$indicator="192.168.1.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::remove([$indicator="192.168.1.2", $indicator_type=Intel::ADDR, $meta=[$source="source2"]]);
	Intel::seen([$host=192.168.1.2, $where=Intel::IN_ANYWHERE]);
	# Trigger shutdown by matching data that should be present
	Intel::seen([$host=10.10.10.10, $where=Intel::IN_ANYWHERE]);
	}

event Cluster::node_up(name: string, id: string)
	{
	# Insert the data once all workers are connected.
	if ( Cluster::local_node_type() == Cluster::MANAGER && Cluster::worker_count == 1 )
		{
		Intel::insert([$indicator="192.168.0.1", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
		Intel::insert([$indicator="192.168.0.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
		Intel::insert([$indicator="192.168.0.2", $indicator_type=Intel::ADDR, $meta=[$source="source2"]]);
		Intel::insert([$indicator="192.168.1.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
		Intel::insert([$indicator="192.168.1.2", $indicator_type=Intel::ADDR, $meta=[$source="source2"]]);
		Intel::insert([$indicator="10.10.10.10", $indicator_type=Intel::ADDR, $meta=[$source="end"]]);

		event test_manager();
		}
	}

global worker_data = 0;
event Intel::insert_indicator(item: Intel::Item)
	{
	# Run test on worker-1 when all items have been inserted
	if ( Cluster::node == "worker-1" )
		{
		++worker_data;
		if ( worker_data == 4 )
			event test_worker();
		}
	}

event Intel::remove_item(item: Item, purge_indicator: bool)
	{
	print fmt("Removing %s (source: %s).", item$indicator, item$meta$source);
	}

event remove_indicator(item: Item)
	{
	print fmt("Purging %s.", item$indicator);
	}

event die()
	{
	terminate();
	}

event Intel::log_intel(rec: Intel::Info)
	{
	print "Logging intel hit!";
	schedule 2sec { die() };
	}

event Cluster::node_down(name: string, id: string)
	{
	# Cascading termination
	schedule 2sec { die() };
	}
