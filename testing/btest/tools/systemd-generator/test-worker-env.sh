# @TEST-DOC: Test that worker_env supports templating and accumulation.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: find dir1 | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth0@1.service.d/10-zeek-systemd-generator.conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth0@2.service.d/10-zeek-systemd-generator.conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth1@1.service.d/10-zeek-systemd-generator.conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth1@2.service.d/10-zeek-systemd-generator.conf

# @TEST-START-FILE config1
[interface eth0]
interface = eth0
workers = 2
worker_env = THIS_IS_OK=42
  TEST_TEMPLATE=worker-${interface_tag}-${worker_index0}-${worker_index}
  TEST_GLOBAL_WORKER_INDICES=${global_worker_index0}.${global_worker_index}

[interface eth1]
interface = eth1
workers = 2
worker_env =
  TEST_TEMPLATE=worker-${interface_tag}-${worker_index0}-${worker_index}
  TEST_GLOBAL_WORKER_INDICES=${global_worker_index0}.${global_worker_index}
# @TEST-END-FILE
