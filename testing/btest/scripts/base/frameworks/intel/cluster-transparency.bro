# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1"],
};
@TEST-END-FILE

@load base/frameworks/control

module Intel;

event remote_connection_handshake_done(p: event_peer)
	{
	# Insert the data once both workers are connected.
	if ( Cluster::local_node_type() == Cluster::MANAGER && Cluster::worker_count == 2 )
		{
		Intel::insert([$host=1.2.3.4,$meta=[$source="manager"]]);
		}
	}

global worker2_data = 0;
global sent_data = F;
event Intel::cluster_new_item(item: Intel::Item)
	{
	if ( ! is_remote_event() )
		return;

	print fmt("cluster_new_item: %s from source %s (from peer: %s)", item$host, item$meta$source, get_event_peer()$descr);

	if ( ! sent_data )
		{
		# We wait to insert data here because we can now be sure the 
		# full cluster is constructed.
		sent_data = T;
		if ( Cluster::node == "worker-1" )
			Intel::insert([$host=123.123.123.123,$meta=[$source="worker-1"]]);
		if ( Cluster::node == "worker-2" )
			Intel::insert([$host=4.3.2.1,$meta=[$source="worker-2"]]);
		}

	# We're forcing worker-2 to die first when it has three intelligence items
	# which were distributed over the cluster (data inserted locally is resent).
	if ( Cluster::node == "worker-2" )
		{
		++worker2_data;
		if ( worker2_data == 3 )
			{
			print "terminating!";
			event Control::shutdown_request();
			}
		}
	}

event remote_connection_closed(p: event_peer)
	{
	# Cascading termination
	#print fmt("disconnected from: %s", p);
	terminate_communication();
	}