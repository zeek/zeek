# @TEST-DOC: Test a few CPU lists.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker@2.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker@3.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-worker@4.service.d/*conf
#
# @TEST-EXEC: mkdir dir2
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config2 dir2
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-worker@2.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-worker@7.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir2/zeek-worker@8.service.d/*conf
#
# @TEST-EXEC: mkdir dir3
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config3 dir3
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-worker@2.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-worker@3.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir3/zeek-worker@4.service.d/*conf

# @TEST-START-FILE config1
interface = eth0
workers = 4
workers_cpu_list = 0-1,8-9
proxies = 1
loggers = 1

base_dir = /opt/zeek
# @TEST-END-FILE
#
# @TEST-START-FILE config2
interface = eth0
workers = 8
workers_cpu_list = 128-240:16
proxies = 1
loggers = 1

base_dir = /opt/zeek
# @TEST-END-FILE
#
# @TEST-START-FILE config3
# interface named like worker :-)
interface = eth0
workers = 4
workers_cpu_list = 42,1-2,43
proxies = 1
loggers = 1

base_dir = /opt/zeek
# @TEST-END-FILE
