# @TEST-DOC: All parties log their cluster metrics at zeek_done() time.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: REP_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff ./manager/out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load base/frameworks/telemetry

@load ./zeromq-test-bootstrap

redef Cluster::Telemetry::core_metrics += {
	Cluster::Telemetry::VERBOSE,
};

redef Cluster::Telemetry::websocket_metrics += {
	Cluster::Telemetry::VERBOSE,
};

global finish: event(name: string);

event zeek_done()
	{
	local ms = Telemetry::collect_metrics("zeek", "cluster_core_*");
	ms += Telemetry::collect_metrics("zeek", "cluster_websocket_*");
	for ( _, m in ms )
		print m$opts$prefix, m$opts$name, m$label_names, m$label_values, m$value;
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek
# If a node comes up that isn't us, send it a finish event.
event Cluster::node_up(name: string, id: string) {
	Cluster::publish(Cluster::nodeid_topic(id), finish, Cluster::node);
}

# If the worker vanishes, finish the test.
event Cluster::node_down(name: string, id: string) {
	terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event Cluster::node_up(name: string, id: string) {
}

event finish(name: string) &is_used {
	terminate();
}
# @TEST-END-FILE
