# @TEST-DOC: Test interpolation of the interface key.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-worker@2.service.d/*conf
#
# @TEST-EXEC: mkdir dir2
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config2 dir2
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-interface-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-interface-worker@2.service.d/*conf
#
# @TEST-EXEC: mkdir dir3
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config3 dir3
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-interface-eth1-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-interface-eth1-worker@2.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-interface-eth1-worker@3.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-interface-eth2-worker@4.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-interface-eth2-worker@5.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-interface-eth2-worker@6.service.d/*conf

# @TEST-START-FILE config1
# You usually want to use worker_index0
interface = netmap::eth1}${worker_index}
workers = 4
workers_cpu_list = 7,8
proxies = 1
loggers = 1

base_dir = /opt/zeek
# @TEST-END-FILE

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
[zeek]

base_dir = /opt/zeek
[interface eth1]
interface = netmap::${interface_tag}}${interface_worker_index0}
workers = 3

[interface eth2]
interface = netmap::${interface_tag}}${interface_worker_index0}
workers = 3

# @TEST-END-FILE
