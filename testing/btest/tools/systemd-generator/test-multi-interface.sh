# @TEST-DOC: Test multiple interface
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: find dir1 | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth0-worker@.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth0-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth0-worker@2.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth1-worker@.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth1-worker@3.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth1-worker@4.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth2-worker@.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth2-worker@5.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth2-worker@6.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth2-worker@7.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth2-worker@8.service.d/*conf
#
# @TEST-START-FILE config1
[zeek]
loggers = 3
proxies = 5

base_dir = /opt/zeek

[interface eth0]
interface = netmap::eth0}${interface_worker_index0}
workers = 2
workers_cpu_list = 2,3
worker_nice = -1
worker_memory_max = 256M

[interface eth1]
interface = af_packet::eth1
worker_args = AF_Packet::fanout_id=42 ignore_checksums=T
workers = 2
workers_cpu_list = 4,5
worker_nice = -2
worker_memory_max = 1G
worker_numa_policy = local

[interface eth2]
interface = af_packet::eth2
worker_args = AF_Packet::fanout_id=43 ignore_checksums=T
workers = 4
workers_cpu_list = 8-12
worker_nice = -3
worker_memory_max = 2G
worker_numa_policy = default
