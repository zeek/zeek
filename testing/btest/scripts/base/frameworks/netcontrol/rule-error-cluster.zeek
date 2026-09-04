# Regression test: NetControl::rule_error must reach the workers.
#
# The manager handles rule_error locally and republishes it to the workers in
# scripts/base/frameworks/netcontrol/cluster.zeek. If that publish omits the
# PluginState argument, Cluster::publish() rejects it on the sending side and
# the workers never see the event at all -- silently, apart from a reporter
# error on the manager.
#
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  "cp ../cluster-layout.zeek . && CLUSTER_NODE=manager  zeek -b %INPUT"
# @TEST-EXEC: btest-bg-run worker-1 "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-1 zeek -b --pseudo-realtime -C -r $TRACES/tls/ecdhe.pcap %INPUT"
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff worker-1/.stdout

redef Log::default_rotation_interval = 0secs;
redef exit_only_after_terminate = T;

@load base/frameworks/netcontrol

event terminate_me()
	{
	terminate();
	}

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
	# This plugin rejects every rule, which is what raises NetControl::rule_error.
	local netcontrol_debug_error = NetControl::create_debug_error("debug-error");
	NetControl::activate(netcontrol_debug_error, 0);
	}

event connection_established(c: connection)
	{
	NetControl::drop_address(c$id$orig_h, 1sec);
	}

# Raised locally on the manager by the plugin, then republished to the workers.
event NetControl::rule_error(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	print "rule error", r$entity$ip, msg;
	terminate();
	}

# Terminate independently of the event under test, so that a regression shows
# up as an empty baseline rather than as a test that hangs until timeout.
event connection_state_remove(c: connection)
	{
	schedule 3sec { terminate_me() };
	}

global peers_lost = 0;

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peers_lost;

	if ( peers_lost == 1 )
		terminate();
	}
