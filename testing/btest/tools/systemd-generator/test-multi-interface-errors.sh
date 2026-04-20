# @TEST-DOC: Test some invalid configurations.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: rm -rf output_dir && mkdir output_dir
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config %INPUT output_dir
# @TEST-EXEC: btest-diff .stderr
interface = eth1
workers = 4

# Do not allow loggers in eth2
interface = eth2
loggers = 7
workers = 4

# @TEST-START-NEXT
interface = eth1
workers = 4

# Do not allow args in eth2
interface = eth2
workers = 4
args =-C

# @TEST-START-NEXT
interface = eth1
workers = 4
worker_numa_policy = local

# Unsupported workers_numa_policy (and deprecated key)
interface = eth2
workers = 4
workers_numa_policy = random

# @TEST-START-NEXT
interface = eth1
workers = 4

# Invalid workers_cpu_list in second interface.
interface = eth2
workers = 4
workers_cpu_list = a,b,c

# @TEST-START-NEXT
# Check three interfaces
interface = eth1
workers = 4

interface = eth2
workers = 4

interface = eth3
workers = 4
proxies = 7
