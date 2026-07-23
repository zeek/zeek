# @TEST-DOC: The zeek-cluster-layout-generator also supports reading a zeek.conf file as is.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C $(pwd)/zeek.conf -o cluster-layout.zeek
# @TEST-EXEC: zeek ./cluster-layout.zeek
# @TEST-EXEC: CLUSTER_NODE=worker-1 zeek ./cluster-layout.zeek --parse-only
# XXX This actually starts listening on the Prometheus endpoint.
# XXX TEST-EXEC: ZEEK_TELEMETRY_LISTEN_ADDRESS=[::1] CLUSTER_NODE=worker-1 zeek ./cluster-layout.zeek --parse-only
# @TEST-EXEC: btest-diff cluster-layout.zeek
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C $(pwd)/zeek-no-metrics.conf -o cluster-layout-no-metrics.zeek
# @TEST-EXEC: zeek ./cluster-layout-no-metrics.zeek
# @TEST-EXEC: btest-diff cluster-layout-no-metrics.zeek

# @TEST-START-FILE zeek.conf
workers = 1
# @TEST-END-FILE
#
# @TEST-START-FILE zeek-no-metrics.conf
workers = 1
address = [::1]
port = 10000
metrics_port = 0
# @TEST-END-FILE
