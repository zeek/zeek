# @TEST-DOC: Use a minimal to check the defaults used.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir normal-dir
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 normal-dir
# @TEST-EXEC: find normal-dir | sort > out
# @TEST-EXEC: btest-diff out
#
# @TEST-EXEC: export TEST_DIFF_CANONIFIER=diff-remove-abspath; for f in normal-dir/*.service ; do btest-diff $f || exit 1; done
# @TEST-EXEC: export TEST_DIFF_CANONIFIER=diff-remove-abspath; for f in normal-dir/*.service ; do btest-diff $f || exit 1; done
# @TEST-EXEC: export TEST_DIFF_CANONIFIER=diff-remove-abspath; for f in normal-dir/*.d/*; do btest-diff $f || exit 1; done

# @TEST-START-FILE config1
interface = eth0
base_dir = /opt/zeek
# @TEST-END-FILE
