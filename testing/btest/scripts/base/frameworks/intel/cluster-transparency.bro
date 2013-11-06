# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff manager-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff worker-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff worker-2/.stdout
# @TEST-EXEC: btest-diff manager-1/intel.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1"],
};
@TEST-END-FILE

@load base/frameworks/control

module Intel;

redef Log::default_rotation_interval=0sec;

event remote_connection_handshake_done(p: event_peer)
	{
	# Insert the data once both workers are connected.
	if ( Cluster::local_node_type() == Cluster::MANAGER && Cluster::worker_count == 2 )
		{
		Intel::insert([$indicator="1.2.3.4", $indicator_type=Intel::ADDR, $meta=[$source="manager"]]);
		}
	}

global worker2_data = 0;
global sent_data = F;
event Intel::cluster_new_item(item: Intel::Item)
	{
	if ( ! is_remote_event() )
		return;

	print fmt("cluster_new_item: %s inserted by %s (from peer: %s)", item$indicator, item$meta$source, get_event_peer()$descr);

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

event Intel::log_intel(rec: Intel::Info)
	{
	event Control::shutdown_request();
	}

event remote_connection_closed(p: event_peer)
	{
	# Cascading termination
	#print fmt("disconnected from: %s", p);
	terminate_communication();
	}
