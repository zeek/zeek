# @TEST-DOC: The zeek-cluster-layout-generator pointed at a directory via -C containing three <hostname>.zeek.conf files.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C $(pwd)/my-cluster -o cluster-layout.zeek
# @TEST-EXEC: zeek ./cluster-layout.zeek
# @TEST-EXEC: CLUSTER_NODE=worker-1 zeek ./cluster-layout.zeek --parse-only
# @TEST-EXEC: ZEEK_TELEMETRY_LISTEN_ADDRESS=[::1] CLUSTER_NODE=worker-1 zeek ./cluster-layout.zeek --parse-only
# @TEST-EXEC: btest-diff cluster-layout.zeek

# @TEST-START-FILE my-cluster/c-mgr.zeek.conf
workers = 0
address = 10.0.0.1
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/wkr-1.zeek.conf
manager = 0
loggers = 0
proxies = 0
workers = 2
address = 10.0.0.2
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/wkr-2.zeek.conf
manager = 0
loggers = 0
proxies = 0
workers = 2
address = 10.0.0.3
# @TEST-END-FILE
