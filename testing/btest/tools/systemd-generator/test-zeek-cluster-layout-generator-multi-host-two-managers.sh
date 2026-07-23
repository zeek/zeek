# @TEST-DOC: The zeek-cluster-layout-generator pointed at a directory via -C containing three <hostname>.zeek.conf files.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C $(pwd)/my-cluster -o cluster-layout.zeek
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-START-FILE my-cluster/c-mgr.zeek.conf
workers = 0
address = 10.0.0.1
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/wkr-1.zeek.conf
manager = 1
workers = 2
address = 10.0.0.2
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/wkr-2.zeek.conf
manager = 0
workers = 2
address = 10.0.0.3
# @TEST-END-FILE
