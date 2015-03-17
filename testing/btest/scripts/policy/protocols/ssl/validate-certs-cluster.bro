# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 "cp ../cluster-layout.bro . && CLUSTER_NODE=manager-1 bro %INPUT"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run proxy-1   "cp ../cluster-layout.bro . && CLUSTER_NODE=proxy-1 bro %INPUT"
# @TEST-EXEC: btest-bg-run proxy-2   "cp ../cluster-layout.bro . && CLUSTER_NODE=proxy-2 bro %INPUT"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  "cp ../cluster-layout.bro . && CLUSTER_NODE=worker-1 bro --pseudo-realtime -C -r $TRACES/tls/missing-intermediate.pcap %INPUT"
# @TEST-EXEC: btest-bg-run worker-2  "cp ../cluster-layout.bro . && CLUSTER_NODE=worker-2 bro --pseudo-realtime -C -r $TRACES/tls/missing-intermediate.pcap %INPUT"
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: cat manager-1/ssl*.log > ssl.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-file-ids btest-diff ssl.log
#

redef Log::default_rotation_interval = 0secs;

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37758/tcp, $manager="manager-1", $workers=set("worker-1", "worker-2")],
	["proxy-2"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37759/tcp, $manager="manager-1", $workers=set("worker-2")],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth1"],
};
@TEST-END-FILE

event terminate_me() {
	terminate();
}

event remote_connection_closed(p: event_peer) {
	schedule 1sec { terminate_me() };
}


@load base/frameworks/cluster
@load protocols/ssl/validate-certs.bro
