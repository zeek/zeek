# @TEST-DOC: run a mini two-node cluster and check that Broker's peering telemetry is available.
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b manager.zeek
# @TEST-EXEC: btest-bg-run worker ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker zeek -b worker.zeek
# @TEST-EXEC: btest-bg-wait 15
#
# @TEST-EXEC: btest-diff manager/out
# @TEST-EXEC: btest-diff worker/out

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT"))],
	["worker"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $manager="manager"],
};
# @TEST-END-FILE

# @TEST-START-FILE common.zeek
@load base/frameworks/cluster
@load policy/frameworks/cluster/experimental

redef exit_only_after_terminate = T;
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0secs;
redef Cluster::retry_interval = 1sec;

function print_metrics(metrics: vector of Telemetry::Metric)
	{
	local f = open("out");

	for (i in metrics)
		{
		local m = metrics[i];
		print f, m$opts$metric_type, m$opts$prefix, m$opts$name, m$label_names, m?$label_values ? m$label_values : vector();
		}

	close(f);
	}

event Cluster::Experimental::cluster_started()
	{
	hook Telemetry::sync();
	local broker_metrics = Telemetry::collect_metrics("zeek_broker_peer_buffer*", "*");
	print_metrics(broker_metrics);
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek
# @TEST-END-FILE
