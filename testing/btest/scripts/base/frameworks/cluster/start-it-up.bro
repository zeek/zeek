# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 bro %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-2 bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_roles=set(Cluster::MANAGER), $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1")],
	["proxy-1"] = [$node_roles=set(Cluster::DATANODE),  $ip=127.0.0.1, $p=37758/tcp, $manager="manager-1", $workers=set("worker-1")],
	["proxy-2"] = [$node_roles=set(Cluster::DATANODE),  $ip=127.0.0.1, $p=37759/tcp, $manager="manager-1", $workers=set("worker-2")],
	["worker-1"] = [$node_roles=set(Cluster::WORKER),   $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $datanode="proxy-1", $interface="eth0"],
	["worker-2"] = [$node_roles=set(Cluster::WORKER),   $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $datanode="proxy-2", $interface="eth1"],
};
@TEST-END-FILE

global fully_connected: event();

global peer_count = 0;

global fully_connected_nodes = 0;

global process_event: function(peer_name: string);

event fully_connected()
	{
	fully_connected_nodes = fully_connected_nodes + 1;
	if ( Cluster::node == "manager-1" )
		{
		if ( peer_count == 4 && fully_connected_nodes == 4 )
			terminate_communication();
		}
	}

redef Cluster::worker2manager_events += {"fully_connected"};
redef Cluster::datanode2manager_events += {"fully_connected"};

function process_event(peer_name: string)
	{
	print "Connected to a peer";
	peer_count = peer_count + 1;
	if ( Cluster::node == "manager-1" )
		{
		if ( peer_count == 4 && fully_connected_nodes == 4 )
			terminate_communication();
		}
	else
		{
		if ( peer_count == 2 )
			event fully_connected();
		}
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	process_event(peer_name);
	}

event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
	{
	process_event(peer_name);
	}

event BrokerComm::outgoing_connection_broken(peer_address: string, peer_port: port, peer_name: string)
	{
	terminate();
	}
