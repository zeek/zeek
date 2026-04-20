# @TEST-DOC: Test the most minimal zeek.conf file.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir mgr-dir worker-1-dir worker-2-dir
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config etc/cluster/mgr.zeek.conf mgr-dir
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config etc/cluster/wkr-1.zeek.conf worker-1-dir
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config etc/cluster/wkr-2.zeek.conf worker-2-dir
# @TEST-EXEC: find mgr-dir | sort > out
# @TEST-EXEC: find worker-1-dir | sort >> out
# @TEST-EXEC: find worker-2-dir | sort >> out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./mgr-dir/zeek-setup.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./worker-1-dir/zeek-setup.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./worker-2-dir/zeek-setup.service
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C etc/cluster -o cluster-layout.zeek
# @TEST-EXEC: btest-diff cluster-layout.zeek

# @TEST-START-FILE etc/cluster/mgr.zeek.conf
manager = 1
loggers = 1
proxies = 2
workers = 0

address = 10.0.0.1
# @TEST-END-FILE
#
# @TEST-START-FILE etc/cluster/wkr-1.zeek.conf
manager = 0
loggers = 0
proxies = 0
archiver = 0

workers = 4
interface = eth0

address = 10.0.0.2
# @TEST-END-FILE
#
# @TEST-START-FILE etc/cluster/wkr-2.zeek.conf
manager = 0
loggers = 0
proxies = 0
archiver = 0

workers = 4
interface = eth0

address = 10.0.0.3
# @TEST-END-FILE
