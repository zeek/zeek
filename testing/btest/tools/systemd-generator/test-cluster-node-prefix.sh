# @TEST-DOC: Test an explicit cluster_node_prefix
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: find dir1 | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-setup.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-manager.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-logger@.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-proxy@.service

# @TEST-START-FILE config1
manager  = 1
loggers  = 1
proxies  = 1
archiver = 1
cluster_node_prefix = c-mgr
base_dir = /opt/zeek
# @TEST-END-FILE
