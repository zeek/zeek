# @TEST-DOC: Test IPv6 cluster
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
# @TEST-EXEC: btest-diff-remove-abspath ./mgr-dir/zeek-setup.service
# @TEST-EXEC: btest-diff-remove-abspath ./worker-1-dir/zeek-setup.service
# @TEST-EXEC: btest-diff-remove-abspath ./worker-2-dir/zeek-setup.service
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C etc/cluster -o cluster-layout.zeek
# @TEST-EXEC: zeek --parse-only ./cluster-layout.zeek
# @TEST-EXEC: btest-diff cluster-layout.zeek

# @TEST-START-FILE etc/cluster/mgr.zeek.conf
[zeek]
manager = 1
loggers = 1
proxies = 2
archiver = 1

address = [2001:400:211::121]
base_dir = /opt/zeek
# @TEST-END-FILE

# @TEST-START-FILE etc/cluster/wkr-1.zeek.conf
[zeek]
address = [2001:400:211::122]
base_dir = /opt/zeek

[interface eth0]
interface = eth0
workers = 4
# @TEST-END-FILE

# @TEST-START-FILE etc/cluster/wkr-2.zeek.conf
[zeek]
address = [2001:400:211::123]
base_dir = /opt/zeek

[interface eth0]
workers = 4
interface = af_packet::eth0

[interface eth1]
workers = 4
interface = af_packet::eth1
worker_args = AF_Packet::fanout_id=42
# @TEST-END-FILE
