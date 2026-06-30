# @TEST-DOC: Test a zeek.conf with only a manager and a cluster-layout.zeek file
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
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-manager.service

# @TEST-START-FILE config1
manager = 1
loggers = 0
proxies = 0
workers = 0
archiver = 0

cluster_layout = /test/etc/zeek/cluster-layout.zeek
base_dir = /test/opt/zeek
# @TEST-END-FILE
