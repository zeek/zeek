# @TEST-DOC: Accept an empty [zeek] section as valid.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: find dir1 | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth0-worker@.service
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth0-worker@1.service.d/*conf
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-interface-eth0-worker@2.service.d/*conf
#
# @TEST-START-FILE config1
[zeek]

[interface eth0]
interface = eth0
workers = 2
# @TEST-END-FILE config1
