# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 "cp ../cluster-layout.bro . && CLUSTER_NODE=manager-1 bro %INPUT"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  "cp ../cluster-layout.bro . && CLUSTER_NODE=worker-1 bro --pseudo-realtime -C -r $TRACES/tls/ecdhe.pcap %INPUT"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-2  "cp ../cluster-layout.bro . && CLUSTER_NODE=worker-2 bro --pseudo-realtime -C -r $TRACES/tls/ecdhe.pcap %INPUT"
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;
#redef exit_only_after_terminate = T;

@load base/frameworks/netcontrol

@if ( Cluster::local_node_type() == Cluster::WORKER )
event bro_init()
	{
	suspend_processing();
	}

event remote_connection_handshake_done(p: event_peer)
	{
	continue_processing();
	}
@endif

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 1sec);
	NetControl::drop_address(id$orig_h, 1sec);
	}

event terminate_me() {
	terminate();
}

event remote_connection_closed(p: event_peer) {
	schedule 1sec { terminate_me() };
}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string &default="")
	{
	print "Rule added", r$id, r$cid;
	if ( r$entity?$ip )
		print |NetControl::find_rules_subnet(r$entity$ip)|;
	}

event NetControl::rule_destroyed(r: NetControl::Rule)
	{
	if ( r$entity?$ip )
		print "Rule destroyed", r$id, r$cid, |NetControl::find_rules_subnet(r$entity$ip)|;
	}
