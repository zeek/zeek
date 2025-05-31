# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  "cp ../cluster-layout.zeek . && CLUSTER_NODE=manager  zeek -b %INPUT"
# @TEST-EXEC: btest-bg-run worker-1 "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-1 zeek -b --pseudo-realtime -C -r $TRACES/tls/ecdhe.pcap %INPUT"

# @TEST-EXEC: $SCRIPTS/wait-for-file manager/lost 45 || (btest-bg-wait -k 1 && false)

# @TEST-EXEC: btest-bg-run worker-2  "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-2 zeek -b --pseudo-realtime -C -r $TRACES/tls/ecdhe.pcap %INPUT"
# This timeout needs to be large to accommodate ZAM compilation delays.
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

redef Log::default_rotation_interval = 0secs;
redef exit_only_after_terminate = T;

@load base/frameworks/netcontrol

@if ( Cluster::local_node_type() == Cluster::WORKER )
event zeek_init()
	{
	suspend_processing();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
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
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 0.5sec);
	NetControl::drop_address(id$orig_h, 1sec);
	}

event terminate_me() {
	terminate();
}

global peers_lost = 0;

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peers_lost;
	system("touch lost");

	if ( peers_lost == 2 )
		schedule 2sec { terminate_me() };
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
		{
		print "Rule destroyed", r$id, r$cid, |NetControl::find_rules_subnet(r$entity$ip)|;
		if ( Cluster::local_node_type() == Cluster::WORKER )
			schedule 2sec { terminate_me() };
		}
	}
