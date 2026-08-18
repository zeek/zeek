# @TEST-DOC: Test the most minimal zeek.conf file.
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
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-logger@.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-proxy@.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-worker@.service
# @TEST-EXEC: btest-diff-remove-abspath ./dir1/zeek-worker@1.service.d/10-zeek-systemd-generator.conf

# @TEST-START-FILE config1
interface = eth0
workers = 1
manager = 1
loggers = 1
proxies = 1
archiver = 1
# @TEST-END-FILE
