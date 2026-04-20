# @TEST-DOC: Use all of the options available.
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
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-logger@.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-proxy@.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-archiver.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth0@.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth0@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth0@2.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth1@.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth1@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker-eth1@2.service.d/*conf
#
# @TEST-START-FILE config1
[zeek]
base_dir = /opt/zeek

args = local tuning/json-logs

env =
  GLOBAL_ENV=1
  LD_PRELOAD=/usr/local/lib/libjemalloc.so

cluster_backend_args =
  policy/frameworks/cluster/backend/broker
  Broker::disable_ssl=T

## Manager configuration
manager = 1
manager_cpu_set = 1-12
manager_memory_max = 1024M
manager_args =
  loaded-by-manager-first
  loaded-by-manager-second

manager_env =
  I_AM_MANAGER=1
  MORE_MANAGER=2

## Logger configuration
loggers = 3
logger_memory_max = 512M
logger_cpu_set = 0,1
logger_args =
  loaded-by-logger-1
  loaded-by-logger-2
logger_env =
  I_AM_LOGGER=1
  MORE_LOGGER=2

## Proxy configuration
proxies = 5
proxy_memory_max = 1024M
proxy_cpu_set = 7,8
proxy_args =
  loaded-by-proxy-1
  loaded-by-proxy-2
proxy_env =
  I_AM_PROXY=1
  MORE_PROXY=2

## Archiver configuration.
archiver = 1
archiver_cpu_set = 4,3,2,1
archiver_memory_max = 64M
archiver_nice = 3
archiver_args =
  -i 3
  -d

archiver_env =
  I_AM_ARCHIVER=1
  MORE_ACHIVER=2

[interface eth0]
interface = netmap::eth0}${worker_index0}
workers = 2
workers_cpu_list = 2,3
worker_nice = -1
worker_memory_max = 256M
worker_args = worker-eth0-1 worker-eth0-2

[interface eth1]
interface = af_packet::eth1
worker_args = AF_Packet::fanout_id=42 ignore_checksums=T worker-eth1-1 worker-eth1-2
workers = 2
workers_cpu_list = 4,5
worker_nice = -2
worker_memory_max = 1G
worker_numa_policy = local
