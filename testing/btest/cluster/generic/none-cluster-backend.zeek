# @TEST-DOC: Ensure an error happens if no cluster backend is selected but Cluster::node is set.
#
# @TEST-EXEC: zeek --parse-only -b %INPUT
# @TEST-EXEC-FAIL: CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -E 's/line [0-9]+/line xxx/g' | $SCRIPTS/diff-remove-abspath" btest-diff .stderr

@load base/frameworks/cluster

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes += {
	["worker-1"] = [$ip=127.0.0.1, $node_type=Cluster::WORKER],
};
# @TEST-END-FILE
