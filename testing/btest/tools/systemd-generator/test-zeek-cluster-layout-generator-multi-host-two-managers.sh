# @TEST-DOC: The zeek-cluster-layout-generator pointed at a directory via -C containing three <hostname>.zeek.conf files.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C $(pwd)/my-cluster -o cluster-layout.zeek
# @TEST-EXEC: btest-diff-remove-abspath .stderr

# @TEST-START-FILE my-cluster/c-mgr.zeek.conf
manager = 1
address = 10.0.0.1
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/wkr-1.zeek.conf
workers = 2
interface = eth0

manager = 1
address = 10.0.0.2
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/wkr-2.zeek.conf
workers = 2
interface = eth0

address = 10.0.0.3
# @TEST-END-FILE
