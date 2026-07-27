# @TEST-DOC: Run zeek-systemd-generator with the default configuration that's in tools/systemd-generator/etc/zeek.conf
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir normal-dir
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config ${TEST_BASE}/../../tools/systemd-generator/etc/zeek/zeek.conf normal-dir
# @TEST-EXEC: find normal-dir | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
