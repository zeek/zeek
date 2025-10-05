# @TEST-DOC: Smoke test the zeek-systemd-generator
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir normal-dir
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 normal-dir
# @TEST-EXEC: find normal-dir | sort > out
# @TEST-EXEC: btest-diff out
#
# @TEST-EXEC: export TEST_DIFF_CANONIFIER=diff-remove-abspath; for f in normal-dir/*.service ; do btest-diff $f || exit 1; done
# @TEST-EXEC: export TEST_DIFF_CANONIFIER=diff-remove-abspath; for f in normal-dir/*.service ; do btest-diff $f || exit 1; done
# @TEST-EXEC: export TEST_DIFF_CANONIFIER=diff-remove-abspath; for f in normal-dir/*.d/*; do btest-diff $f || exit 1; done

# @TEST-START-FILE config1
interface = af_packet::eth0
workers = 4
workers_cpu_list = 13,14
proxies = 2
loggers = 3

user = test-zeek-user
group = test-zeek-group

args = ignore_checksums=T
cluster_backend_args = the-cluster-backend -B plugin-Zeek-Cluster_Backend_ZeroMQ

address = 127.0.2.1
port = 20000
metrics_port = 30000
metrics_address = 10.0.0.1

manager_nice = -1
proxy_nice = -2
logger_nice = -3
worker_nice = -19

manager_memory_max = 2001M
logger_memory_max = 2001000K
proxy_memory_max = 2000000000
worker_memory_max = 1G

base_dir = /opt/zeek
# @TEST-END-FILE
