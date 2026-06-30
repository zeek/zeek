# @TEST-DOC: Test that when manager = 0, the cluster_layout option has to be provided.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff .stderr
#
# @TEST-START-FILE config1
# No manager, but also no cluster_layout
interface = eth0
manager = 0
# @TEST-END-FILE
