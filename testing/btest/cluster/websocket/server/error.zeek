# @TEST-DOC: Ensure an error happens when loading websocket/server with a clsuter-layout but no backend.
#
# @TEST-EXEC-FAIL: unset ZEEK_ALLOW_INIT_ERRORS; CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load frameworks/cluster/websocket/server

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes += {
	["worker-1"] = [$ip=127.0.0.1, $node_type=Cluster::WORKER],
};
# @TEST-END-FILE
