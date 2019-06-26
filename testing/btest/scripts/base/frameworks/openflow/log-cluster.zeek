# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
#
# @TEST-EXEC: btest-bg-run manager-1 "cp ../cluster-layout.zeek . && CLUSTER_NODE=manager-1 zeek %INPUT"
# @TEST-EXEC: btest-bg-run worker-1  "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-1 zeek --pseudo-realtime -C -r $TRACES/smtp.trace %INPUT"
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/openflow.log

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

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

