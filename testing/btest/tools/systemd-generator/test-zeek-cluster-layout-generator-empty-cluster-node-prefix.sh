# @TEST-DOC: The zeek-cluster-layout-generator with an empty cluster_node_prefix for the host with the manager.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C $(pwd)/my-cluster -o cluster-layout.zeek
# @TEST-EXEC: zeek ./cluster-layout.zeek -e 'print "== nodes", Cluster::nodes' >> out
# @TEST-EXEC: btest-diff out

# @TEST-START-FILE my-cluster/mug-manager.zeek.conf
manager = 1
loggers = 1
proxies = 2
cluster_node_prefix =
cluster_address = 10.0.0.1
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/mug-worker-1.zeek.conf
cluster_node_prefix = worker-host-1
cluster_address = 10.0.0.2
interface = eth0
workers = 2
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/mug-worker-2.zeek.conf
cluster_node_prefix = worker-host-2
cluster_address = 10.0.0.2
interface = eth0
workers = 2
# @TEST-END-FILE
