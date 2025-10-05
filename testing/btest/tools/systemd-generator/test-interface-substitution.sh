# @TEST-DOC: Test interpolation of the interface key.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: CONFIG_FILE=config1 ${BUILD}/tools/systemd-generator/zeek-systemd-generator dir1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker@2.service.d/*conf
#
# @TEST-EXEC: mkdir dir2
# @TEST-EXEC: CONFIG_FILE=config2 ${BUILD}/tools/systemd-generator/zeek-systemd-generator dir2
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-worker@2.service.d/*conf
# #
# @TEST-EXEC: mkdir dir3
# @TEST-EXEC: CONFIG_FILE=config3 ${BUILD}/tools/systemd-generator/zeek-systemd-generator dir3
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-worker@2.service.d/*conf

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
#
# @TEST-START-FILE config3
# interface named like worker :-)
interface = af_packet::${worker_name}-${worker_cpu}
workers = 4
workers_cpu_list = 42,43,44,45
proxies = 1
loggers = 1

base_dir = /opt/zeek
# @TEST-END-FILE
