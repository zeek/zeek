# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 "cp ../cluster-layout.bro . && CLUSTER_NODE=manager-1 bro %INPUT"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  "cp ../cluster-layout.bro . && CLUSTER_NODE=worker-1 bro --pseudo-realtime -C -r $TRACES/smtp.trace %INPUT"
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/openflow.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;
#redef exit_only_after_terminate = T;

@load base/protocols/conn
@load base/frameworks/openflow

global of_controller: OpenFlow::Controller;

event bro_init()
	{
	of_controller = OpenFlow::log_new(42);
	}

event connection_established(c: connection)
	{
	print "conn established";
	local match = OpenFlow::match_conn(c$id);
	local match_rev = OpenFlow::match_conn(c$id, T);

	local flow_mod: OpenFlow::ofp_flow_mod = [
		$cookie=42,
		$command=OpenFlow::OFPFC_ADD,
		$idle_timeout=30,
		$priority=5
	];

	OpenFlow::flow_mod(of_controller, match, flow_mod);
	OpenFlow::flow_mod(of_controller, match_rev, flow_mod);
	}

event terminate_me() {
	terminate();
}

event remote_connection_closed(p: event_peer) {
	schedule 1sec { terminate_me() };
}

