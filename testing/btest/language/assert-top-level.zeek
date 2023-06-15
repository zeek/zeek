# Doesn't make sense for ZAM as it ignores assert's.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
# @TEST-EXEC-FAIL: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

assert getpid() > 0;
assert getpid() == 0, fmt("my pid greater 0? %s", getpid() > 0);
