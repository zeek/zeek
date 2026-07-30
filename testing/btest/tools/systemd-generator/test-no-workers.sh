# @TEST-DOC: Test a zeek.conf with no workers and a cluster-layout.zeek file
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: find dir1 | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-setup.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-manager.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-proxy@.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-logger@.service

# @TEST-START-FILE config1
manager = 1
loggers = 3
proxies = 4
archiver = 1

# This is allowed in the section-less format
workers = 0
interface =

base_dir = /test/opt/zeek
# @TEST-END-FILE
