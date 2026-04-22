# @TEST-DOC: Test some invalid configurations.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: rm -rf output_dir && mkdir output_dir
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config %INPUT output_dir
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# missing interface in interface section
[interface eth1]
workers = 4

# @TEST-START-NEXT
# missing interface section
[interface eth1]
interface = eth1

# @TEST-START-NEXT
[interface eth1]
interface = eth1
workers = 4

# Do not allow loggers in eth2
[interface eth2]
interface = eth2
loggers = 7
workers = 4

# @TEST-START-NEXT
[interface eth1]
interface = eth1
workers = 4

# Do not allow args in eth2
[interface eth2]
interface = eth2
workers = 4
args =-C

# @TEST-START-NEXT
[interface eth1]
interface = eth1
workers = 4
worker_numa_policy = local

# Unsupported workers_numa_policy (and deprecated key)
[interface eth2]
interface = eth2
workers = 4
workers_numa_policy = random

# @TEST-START-NEXT
[interface eth1]
interface = eth1
workers = 4

# Invalid workers_cpu_list in second interface.
[interface eth2]
interface = eth2
workers = 4
workers_cpu_list = a,b,c

# @TEST-START-NEXT
# Check three interfaces
[interface eth1]
interface = eth1
workers = 4

[interface eth2]
interface = eth2
workers = 4

[interface eth3]
interface = eth3
workers = 4
proxies = 7

# @TEST-START-NEXT
# Cannot mix unnamed and interface section
loggers = 3

[interface eth0]
interface = eth0
workers = 2

# @TEST-START-NEXT
# Bad interface tag
[interface eth!a]
interface = eth0
workers = 2

# @TEST-START-NEXT
# Bad interface tag
[interface eth eth]
interface = eth0
workers = 2

# @TEST-START-NEXT
# Bad interface tag
[interface eth-eth]
interface = eth0
workers = 2

# @TEST-START-NEXT
# Duplicate option
[interface eth0]
interface = eth0
workers = 2
workers = 2

# @TEST-START-NEXT
# Missing equals in option
[interface eth0]
interface = eth0
workers 2
workers = 2

# @TEST-START-NEXT
# Missing equals in option
[zeek]
loggers 7

[interface eth0]
interface = eth0
workers = 2
