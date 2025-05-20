# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff manager/intel.log

@load base/frameworks/intel
@load policy/frameworks/cluster/experimental

module Intel;

redef Log::default_rotation_interval=0sec;

event test_worker()
	{
	Intel::remove([$indicator="192.168.1.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::remove([$indicator="192.168.1.2", $indicator_type=Intel::ADDR, $meta=[$source="source2"]]);
	Intel::seen([$host=192.168.1.2, $where=Intel::IN_ANYWHERE]);
	# Trigger shutdown by matching data that should be present
	Intel::seen([$host=10.10.10.10, $where=Intel::IN_ANYWHERE]);
	}

event test_manager()
	{
	Intel::remove([$indicator="192.168.0.1", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::seen([$host=192.168.0.1, $where=Intel::IN_ANYWHERE]);
	Intel::remove([$indicator="192.168.0.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]], T);
	Intel::seen([$host=192.168.0.2, $where=Intel::IN_ANYWHERE]);

	Broker::publish(Cluster::worker_topic, test_worker);
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node != "manager" )
		return;

	# Insert the data once all workers are connected.
	Intel::insert([$indicator="192.168.0.1", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::insert([$indicator="192.168.0.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::insert([$indicator="192.168.0.2", $indicator_type=Intel::ADDR, $meta=[$source="source2"]]);
	Intel::insert([$indicator="192.168.1.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::insert([$indicator="192.168.1.2", $indicator_type=Intel::ADDR, $meta=[$source="source2"]]);
	Intel::insert([$indicator="10.10.10.10", $indicator_type=Intel::ADDR, $meta=[$source="end"]]);

	event test_manager();
	}

event Intel::remove_item(item: Item, purge_indicator: bool)
	{
	print fmt("Removing %s (source: %s).", item$indicator, item$meta$source);
	}

global purge_count = 0;
global got_intel_hit = F;

function check_termination_condition()
	{
	if ( Cluster::node == "worker-1" && purge_count == 3 && got_intel_hit )
		terminate();
	}

event set_intel_hit()
	{
	got_intel_hit = T;
	check_termination_condition();
	}

event remove_indicator(item: Item)
	{
	++purge_count;
	print fmt("Purging %s.", item$indicator);
	check_termination_condition();
	}

event Intel::log_intel(rec: Intel::Info)
	{
	print "Logging intel hit!";
	Broker::publish(Cluster::worker_topic, set_intel_hit);
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
