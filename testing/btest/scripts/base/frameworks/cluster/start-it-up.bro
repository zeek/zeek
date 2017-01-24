# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run data-1   BROPATH=$BROPATH:.. CLUSTER_NODE=data-1 bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff data-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_roles=set(Cluster::MANAGER, Cluster::LOGGER), $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["data-1"] = [$node_roles=set(Cluster::DATANODE),   $ip=127.0.0.1, $p=37758/tcp, $manager="manager-1", $workers=set("worker-1", "worker-2")],
	["worker-1"] = [$node_roles=set(Cluster::WORKER),   $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $datanodes=set("data-1"), $interface="eth0"],
	["worker-2"] = [$node_roles=set(Cluster::WORKER),   $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $datanodes=set("data-1"), $interface="eth1"],
};
@TEST-END-FILE

global fully_connected: event();

global peer_count = 0;

global fully_connected_nodes = 0;

global process_connection: function(peer_name: string);

event fully_connected()
	{
	if ( Cluster::node == "manager-1" )
		{
		++fully_connected_nodes;

		if ( peer_count == 3 && fully_connected_nodes == 3 )
			terminate();
		}
	}

redef Cluster::worker2manager_events += {"fully_connected"};
redef Cluster::datanode2manager_events += {"fully_connected"};

function process_connection(peer_name: string)
	{
	print "Connected to a peer";
	++peer_count;
	if ( Cluster::node == "data-1" )
		{
		if ( peer_count == 3 )
			event fully_connected();
		}
	else if ( Cluster::node == "worker-1" || Cluster::node == "worker-2" )
		{
		if ( peer_count == 2 )
			event fully_connected();
		}
	}

event Broker::incoming_connection_established(peer_name: string)
	{
	process_connection(peer_name);
	}

event Broker::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
	{
	process_connection(peer_name);
	}

event Broker::outgoing_connection_broken(peer_address: string, peer_port: port, peer_name: string)
	{
	terminate();
	}
