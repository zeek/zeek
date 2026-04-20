# @TEST-DOC: Test ext_path setting
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-manager.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-1-worker@.service

# @TEST-START-FILE config1
interface = eth0
workers = 1
proxies = 1
loggers = 1
ext_zeek_path = /opt/myzeek/mypackages:/opt/morepackages

base_dir = /opt/zeek
# @TEST-END-FILE
