# @TEST-DOC: Test interpolation of the interface key.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker@2.service.d/*conf
#
# @TEST-EXEC: mkdir dir2
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config2 dir2
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-worker@2.service.d/*conf

# @TEST-START-FILE config1
interface = netmap::eth1}${worker_index}
workers = 4
workers_cpu_list = 7,8
proxies = 1
loggers = 1

base_dir = /opt/zeek
# @TEST-END-FILE
#
# @TEST-START-FILE config2
interface = netmap::eth1}${worker_index0}@${worker_cpu}
workers = 4
workers_cpu_list = 7,8
proxies = 1
loggers = 1

base_dir = /opt/zeek
# @TEST-END-FILE
