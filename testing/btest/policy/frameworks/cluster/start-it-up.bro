# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 bro %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-2 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait -k 2
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1")],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37758/tcp, $manager="manager-1", $workers=set("worker-1")],
	["proxy-2"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37759/tcp, $manager="manager-1", $workers=set("worker-2")],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $proxy="proxy-2", $interface="eth1"],
	["control"] = [$node_type=Cluster::CONTROL,   $ip=127.0.0.1, $p=37762/tcp],
	["time-machine"] = [$node_type=Cluster::TIME_MACHINE, $ip=127.0.0.1, $p=37763/tcp],
};
@TEST-END-FILE

@load frameworks/cluster

# Enable local logging on every node so that we can get the loaded_scripts log.
redef Log::enable_local_logging = T;

event remote_connection_handshake_done(p: event_peer)
	{
	local me = Cluster::nodes[Cluster::node];
	if ( ( me$node_type == Cluster::MANAGER &&
		 |Communication::connected_peers| == 4 ) ||
		 ( |Communication::connected_peers| == 2 ) )
		{
		print "Successfully connected to all of my peers";
		}
	}