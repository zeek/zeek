# @TEST-DOC: Test that when specifying cluster_layout, there'll be a cp command rendered into zeek-setup.service
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: find dir1 | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-setup.service

# @TEST-START-FILE config1
interface = eth0
cluster_layout = /test/etc/zeek/cluster-layout.zeek
base_dir = /test/opt/zeek
# @TEST-END-FILE
