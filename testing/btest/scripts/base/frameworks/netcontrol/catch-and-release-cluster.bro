# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 "cp ../cluster-layout.bro . && CLUSTER_NODE=manager-1 bro %INPUT"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  "cp ../cluster-layout.bro . && CLUSTER_NODE=worker-1 bro --pseudo-realtime -C -r $TRACES/tls/ecdhe.pcap %INPUT"
# @TEST-EXEC: btest-bg-run worker-2  "cp ../cluster-layout.bro . && CLUSTER_NODE=worker-2 bro --pseudo-realtime -C -r $TRACES/tls/ecdhe.pcap %INPUT"
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v ^# | $SCRIPTS/diff-remove-timestamps' btest-diff manager-1/netcontrol.log
# @TEST-EXEC: btest-diff manager-1/netcontrol_catch_release.log
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

@load base/frameworks/netcontrol
redef NetControl::catch_release_warn_blocked_ip_encountered = T;

global ready_for_data_1: event();
global ready_for_data_2: event();
redef Cluster::manager2worker_events += /^ready_for_data_(1|2)$/;

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;
event remote_connection_handshake_done(p: event_peer) &priority=-5
	{
	++peer_count;
	if ( peer_count == 2 )
		{
		event ready_for_data_1();
		schedule 1.5sec { ready_for_data_2() };
		}
	}

@endif

@if ( Cluster::local_node_type() == Cluster::WORKER )
event bro_init()
	{
	print "Suspend", Cluster::node;
	suspend_processing();
	}

@endif

@if ( Cluster::node == "worker-1" )
event ready_for_data_1()
	{
	print "Resume", Cluster::node;
	continue_processing();
	}
@endif

@if ( Cluster::node == "worker-2" )
event ready_for_data_2()
	{
	print "Resume", Cluster::node;
	continue_processing();
	}
@endif

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

global i: count = 0;

event connection_established(c: connection)
	{
	print "Connection established";
	local id = c$id;
	local info = NetControl::get_catch_release_info(id$orig_h);
	print "Info", info;
	NetControl::drop_address_catch_release(id$orig_h);
	if ( info$current_block_id != "" )
		{
		NetControl::unblock_address_catch_release(id$orig_h);
		}
	}

@if ( Cluster::node == "worker-1" )
event connection_established(c: connection)
	{
	NetControl::drop_address(8.8.8.8, 0.1secs);
	NetControl::drop_address_catch_release(8.8.8.8);
	}
@endif

@if ( Cluster::node == "worker-2" )
event connection_established(c: connection)
	{
	NetControl::catch_release_seen(8.8.8.8);
	}
@endif

event NetControl::catch_release_block_new(a: addr, b: NetControl::BlockInfo)
	{
	print "New block", a, b;
	}

event NetControl::catch_release_block_delete(a: addr)
	{
	print "Delete block", a;
	}

event terminate_me() {
	print "Terminate";
	terminate();
}

event remote_connection_closed(p: event_peer) {
	schedule 1sec { terminate_me() };
}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "Scheduling terminate";
	schedule 3sec { terminate_me() };
	}
@endif
