# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait -k 3
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1",$interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1",$interface="eth1"],
};
@TEST-END-FILE

event remote_connection_handshake_done(p: event_peer)
	{
	# Insert the data once both workers are connected.
	if ( Cluster::local_node_type() == Cluster::MANAGER && Cluster::worker_count == 2 )
		{
		Intel::insert([$ip=1.2.3.4,$meta=[$source="foobar", $class=Intel::MALICIOUS, $tags=set("a","b","c")]]);
		}
	}

event remote_connection_closed(p: event_peer)
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER && Cluster::worker_count == 0 )
		terminate_communication();
	}

# This should print out a single time on the manager and each worker 
# due to the cluster transparency.
event Intel::new_item(item: Intel::Item)
	{
	print item$ip;
	print item$meta$tags;
	print item$meta$source;

	if ( Cluster::local_node_type() == Cluster::WORKER )
		terminate_communication();
	}