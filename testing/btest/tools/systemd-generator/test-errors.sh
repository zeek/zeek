# @TEST-DOC: Test some invalid configurations.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: rm -rf output_dir && mkdir output_dir
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config %INPUT output_dir
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
manager_nice =
proxy_nice = 100
logger_nice = abc
worker_nice = cba
archiver_nice = 10

# @TEST-START-NEXT
manager_memory_max =
logger_memory_max = 17P
worker_memory_max = bug
proxy_memory_max = = -23
archiver_memory_max = 64M

# @TEST-START-NEXT
manager_cpu_set  = a,b,c
logger_cpu_set =
proxy_cpu_set = -1,-2
archiver_cpu_set = 1,2,3
