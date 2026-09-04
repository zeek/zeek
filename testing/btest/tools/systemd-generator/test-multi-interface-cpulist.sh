# @TEST-DOC: Focused regression test for when the global host worker index was used instead of the local interface section worker index to determine CPUs from the workers_cpu_list.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: grep CPUAffinity ./dir1/zeek-worker-eth*/*.conf | sort >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
#
# @TEST-START-FILE config1
[zeek]
manager = 1
loggers = 3
proxies = 5

base_dir = /opt/zeek

[interface eth0]
interface = eth0
workers = 2
workers_cpu_list = 2

[interface eth1]
interface = eth1
workers = 3
workers_cpu_list = 5,6,7

[interface eth2]
interface = eth2
workers = 5
workers_cpu_list = 10-18:2
