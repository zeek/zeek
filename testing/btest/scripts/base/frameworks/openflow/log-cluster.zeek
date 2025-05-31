# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  "cp ../cluster-layout.zeek . && CLUSTER_NODE=manager  zeek %INPUT"
# @TEST-EXEC: btest-bg-run worker-1 "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-1 zeek --pseudo-realtime -C -r $TRACES/smtp.trace %INPUT"
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff manager/openflow.log

redef Log::default_rotation_interval = 0secs;
#redef exit_only_after_terminate = T;

@load base/protocols/conn
@load base/frameworks/openflow

global of_controller: OpenFlow::Controller;

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

event zeek_init()
	{
	of_controller = OpenFlow::log_new(42);
	}

event terminate_me()
	{
	terminate();
	}

global done = F;

event connection_established(c: connection)
	{
	if ( done )
		return;

	done = T;

	print "conn established";

	local match = OpenFlow::match_conn(c$id);
	local match_rev = OpenFlow::match_conn(c$id, T);

	local flow_mod: OpenFlow::ofp_flow_mod = [
		$cookie=OpenFlow::generate_cookie(42),
		$command=OpenFlow::OFPFC_ADD,
		$idle_timeout=30,
		$priority=5
	];

	OpenFlow::flow_mod(of_controller, match, flow_mod);
	OpenFlow::flow_mod(of_controller, match_rev, flow_mod);

	schedule 2sec { terminate_me() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	schedule 2sec { terminate_me() };
	}

