# @TEST-EXEC-FAIL: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff-remove-abspath .stderr

assert getpid() > 0;
assert getpid() == 0, fmt("my pid greater 0? %s", getpid() > 0);
